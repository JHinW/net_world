package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// PeerConnection [Infrastructure Layer] maintains a reusable Tailcat client and warm TCP stream
// to a single sibling peer (identified by tc_addr + remote_port).
type PeerConnection struct {
	TCAddr     tailcat.Addr
	RemotePort uint16
	ClientKey  key.NodePrivate
	Vault      *IdentityVault
	Logf       logger.Logf

	mu               sync.Mutex
	client           *tailcat.Client
	conn             net.Conn
	reader           *bufio.Reader
	inFlight         atomic.Bool
	lastActivityNano atomic.Int64
}

// NewPeerConnection creates a PeerConnection for a target sibling node.
func NewPeerConnection(tcAddr tailcat.Addr, remotePort uint16, clientKey key.NodePrivate, vault *IdentityVault, logf logger.Logf) *PeerConnection {
	if remotePort == 0 {
		remotePort = 19100
	}
	return &PeerConnection{
		TCAddr:     tcAddr,
		RemotePort: remotePort,
		ClientKey:  clientKey,
		Vault:      vault,
		Logf:       logf,
	}
}

func (p *PeerConnection) closeConnLocked() {
	if p.conn != nil {
		_ = p.conn.Close()
		p.conn = nil
		p.reader = nil
	}
}

func (p *PeerConnection) resetClientLocked() {
	p.closeConnLocked()
	if p.client != nil {
		_ = p.client.Close()
		p.client = nil
	}
}

// Close shuts down both the warm TCP connection and the underlying tailcat.Client.
func (p *PeerConnection) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resetClientLocked()
}

func (p *PeerConnection) dialWarmConnLocked(timeout time.Duration) error {
	p.closeConnLocked()
	dialStart := time.Now()

	if p.client != nil {
		warmTimeout := timeout
		if timeout > 2500*time.Millisecond {
			warmTimeout = min(timeout/3, 2500*time.Millisecond)
		}
		ctx, cancel := context.WithTimeout(context.Background(), warmTimeout)
		c, err := p.client.DialTCPPort(ctx, p.RemotePort)
		cancel()
		if err == nil {
			p.conn = c
			p.reader = bufio.NewReaderSize(c, 64*1024)
			return nil
		}
		p.resetClientLocked()
	}

	remBudget := max(1500*time.Millisecond, timeout-time.Since(dialStart))
	cl, c, _, err := p.Vault.DialWithFailover(
		context.Background(),
		string(p.TCAddr),
		p.ClientKey,
		remBudget,
		p.Logf,
		func(dctx context.Context, candClient *tailcat.Client) (net.Conn, error) {
			return candClient.DialTCPPort(dctx, p.RemotePort)
		},
	)
	if err != nil {
		return err
	}
	p.client = cl
	p.conn = c
	p.reader = bufio.NewReaderSize(c, 64*1024)
	return nil
}

func (p *PeerConnection) writeJSONLineLocked(payload map[string]any, writeTimeout time.Duration) error {
	if p.conn == nil {
		return fmt.Errorf("no active connection")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	_ = p.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err = p.conn.Write(raw)
	return err
}

func (p *PeerConnection) readJSONLineLocked(deadline time.Time) (map[string]any, error) {
	if p.conn == nil || p.reader == nil {
		return nil, fmt.Errorf("no active connection")
	}
	_ = p.conn.SetReadDeadline(deadline)
	for {
		line, err := p.reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || !strings.HasPrefix(trimmed, "{") {
			continue
		}
		var evt map[string]any
		if err := json.Unmarshal([]byte(trimmed), &evt); err != nil {
			continue
		}
		return evt, nil
	}
}

func (p *PeerConnection) pingLocked(timeoutSec float64, token string) (map[string]any, error) {
	effTimeout := time.Duration(max(0.5, timeoutSec) * float64(time.Second))
	overallStart := time.Now()
	for attempt := 0; attempt < 2; attempt++ {
		wasAlive := p.conn != nil
		attemptBudget := max(1000*time.Millisecond, effTimeout-time.Since(overallStart))
		if attempt == 0 && wasAlive && attemptBudget > 1800*time.Millisecond {
			attemptBudget = 1800 * time.Millisecond
		}

		dialStart := time.Now()
		if !wasAlive {
			if err := p.dialWarmConnLocked(attemptBudget); err != nil {
				return nil, fmt.Errorf("dial failed: %w", err)
			}
		}

		req := map[string]any{
			"op":    "ping",
			"token": token,
		}
		if err := p.writeJSONLineLocked(req, 1500*time.Millisecond); err != nil {
			p.closeConnLocked()
			if attempt == 0 && wasAlive {
				continue
			}
			return nil, err
		}

		remaining := attemptBudget - time.Since(dialStart)
		if remaining < 300*time.Millisecond {
			remaining = 300 * time.Millisecond
		}
		deadline := time.Now().Add(remaining)
		for time.Now().Before(deadline) {
			evt, err := p.readJSONLineLocked(deadline)
			if err != nil {
				break
			}
			etype, _ := evt["type"].(string)
			if etype == "pong" {
				p.lastActivityNano.Store(time.Now().UnixNano())
				health, _ := evt["health"].(map[string]any)
				if health == nil {
					health = map[string]any{}
				}
				return health, nil
			}
			if etype == "error" {
				errMsg, _ := evt["error"].(string)
				if errMsg == "" {
					errMsg = "remote error"
				}
				return nil, fmt.Errorf("%s", errMsg)
			}
		}

		p.closeConnLocked()
		if !(attempt == 0 && wasAlive) {
			break
		}
	}
	return nil, fmt.Errorf("stdio ping 超时 (%.0fs)", timeoutSec)
}

// Ping probes the sibling peer over the warm stream, fast-returning if a streaming task is actively in flight.
func (p *PeerConnection) Ping(timeoutSec float64, token string) (map[string]any, error) {
	lastNano := p.lastActivityNano.Load()
	if p.inFlight.Load() && lastNano > 0 && time.Since(time.Unix(0, lastNano)) < 120*time.Second {
		return map[string]any{"status": "streaming_in_flight"}, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pingLocked(timeoutSec, token)
}

// StreamTask sends a task envelope over the warm peer stream and invokes emit for each ack/step/result event.
func (p *PeerConnection) StreamTask(
	connectTimeoutSec float64,
	idleTimeoutSec float64,
	token string,
	envelope map[string]any,
	emit func(map[string]any),
) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, err := p.pingLocked(connectTimeoutSec, token); err != nil {
		emit(map[string]any{
			"type":  "error",
			"error": err.Error(),
		})
		return
	}

	req := map[string]any{
		"op":       "task",
		"token":    token,
		"envelope": envelope,
	}
	if err := p.writeJSONLineLocked(req, 5*time.Second); err != nil {
		p.closeConnLocked()
		emit(map[string]any{
			"type":  "error",
			"error": fmt.Sprintf("write task failed: %v", err),
		})
		return
	}

	now := time.Now()
	p.lastActivityNano.Store(now.UnixNano())
	p.inFlight.Store(true)
	defer p.inFlight.Store(false)

	idleDur := time.Duration(max(5.0, idleTimeoutSec) * float64(time.Second))
	maxWallDur := max(idleDur*2, idleDur+60*time.Second)
	hardDeadline := now.Add(maxWallDur)

	for {
		readDeadline := time.Now().Add(idleDur)
		if readDeadline.After(hardDeadline) {
			readDeadline = hardDeadline
		}
		if time.Now().After(readDeadline) {
			p.closeConnLocked()
			emit(map[string]any{
				"type":  "error",
				"error": fmt.Sprintf("等待对端响应超时 (空闲超过 %.0fs)", idleTimeoutSec),
			})
			return
		}

		evt, err := p.readJSONLineLocked(readDeadline)
		if err != nil {
			p.closeConnLocked()
			emit(map[string]any{
				"type":  "error",
				"error": fmt.Sprintf("对端流连接断开: %v", err),
			})
			return
		}

		p.lastActivityNano.Store(time.Now().UnixNano())
		etype, _ := evt["type"].(string)
		switch etype {
		case "ack", "step":
			emit(evt)
		case "result", "error":
			emit(evt)
			return
		}
	}
}

// OutboundMultiplexer [Infrastructure Layer] manages the pool of PeerConnections
// and multiplexes concurrent JSONL requests/responses over a single stdio pipe.
type OutboundMultiplexer struct {
	Vault     *IdentityVault
	ClientKey key.NodePrivate
	Logf      logger.Logf

	peersMu sync.Mutex
	peers   map[string]*PeerConnection

	writeMu sync.Mutex
	out     io.Writer
}

// NewOutboundMultiplexer constructs an OutboundMultiplexer bound to the given output stream.
func NewOutboundMultiplexer(vault *IdentityVault, clientKey key.NodePrivate, out io.Writer, logf logger.Logf) *OutboundMultiplexer {
	if logf == nil {
		logf = logger.Discard
	}
	return &OutboundMultiplexer{
		Vault:     vault,
		ClientKey: clientKey,
		Logf:      logf,
		peers:     make(map[string]*PeerConnection),
		out:       out,
	}
}

func (m *OutboundMultiplexer) getPeer(tcAddr string, remotePort uint16) *PeerConnection {
	if remotePort == 0 {
		remotePort = 19100
	}
	keyStr := fmt.Sprintf("%s:%d", strings.TrimSpace(tcAddr), remotePort)
	m.peersMu.Lock()
	defer m.peersMu.Unlock()
	if pc, ok := m.peers[keyStr]; ok {
		return pc
	}
	pc := NewPeerConnection(tailcat.Addr(strings.TrimSpace(tcAddr)), remotePort, m.ClientKey, m.Vault, m.Logf)
	m.peers[keyStr] = pc
	return pc
}

// Emit writes a JSONL event to stdout safely across concurrent goroutines.
func (m *OutboundMultiplexer) Emit(obj map[string]any) {
	raw, err := json.Marshal(obj)
	if err != nil {
		return
	}
	raw = append(raw, '\n')
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	_, _ = m.out.Write(raw)
}

// ServeStdio reads JSONL multiplexed commands from in until EOF and dispatches each in a goroutine.
func (m *OutboundMultiplexer) ServeStdio(in io.Reader) {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	var wg sync.WaitGroup
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var msg map[string]any
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue
		}
		wg.Add(1)
		go func(cmd map[string]any) {
			defer wg.Done()
			m.handleCommand(cmd)
		}(msg)
	}
	wg.Wait()
}

func (m *OutboundMultiplexer) handleCommand(msg map[string]any) {
	muxID, _ := msg["mux_id"].(string)
	op, _ := msg["op"].(string)
	peerID, _ := msg["peer_id"].(string)
	tcAddr, _ := msg["tc_addr"].(string)
	if m.Vault != nil {
		tcAddr = m.Vault.ResolvePeerAddr(peerID, tcAddr)
	}
	remotePort := uint16(19100)
	if rp, ok := msg["remote_port"].(float64); ok && rp > 0 {
		remotePort = uint16(rp)
	}
	token, _ := msg["token"].(string)

	emitWithMux := func(evt map[string]any) {
		out := make(map[string]any, len(evt)+1)
		for k, v := range evt {
			out[k] = v
		}
		if muxID != "" {
			out["mux_id"] = muxID
		}
		m.Emit(out)
	}

	if tcAddr == "" {
		emitWithMux(map[string]any{"type": "error", "error": "missing tc_addr"})
		return
	}

	peerConn := m.getPeer(tcAddr, remotePort)
	switch op {
	case "ping":
		timeoutSec := 8.0
		if t, ok := msg["timeout"].(float64); ok && t > 0 {
			timeoutSec = t
		}
		health, err := peerConn.Ping(timeoutSec, token)
		if err != nil {
			emitWithMux(map[string]any{"type": "error", "error": err.Error()})
			return
		}
		emitWithMux(map[string]any{"type": "pong", "health": health})

	case "task":
		connectTimeout := 10.0
		if ct, ok := msg["connect_timeout"].(float64); ok && ct > 0 {
			connectTimeout = ct
		}
		idleTimeout := 120.0
		if it, ok := msg["timeout"].(float64); ok && it > 0 {
			idleTimeout = it
		}
		envelope, _ := msg["envelope"].(map[string]any)
		peerConn.StreamTask(connectTimeout, idleTimeout, token, envelope, emitWithMux)

	default:
		emitWithMux(map[string]any{"type": "error", "error": "unknown_op:" + op})
	}
}

// CloseAll closes all pooled peer connections.
func (m *OutboundMultiplexer) CloseAll() {
	m.peersMu.Lock()
	peers := make([]*PeerConnection, 0, len(m.peers))
	for _, p := range m.peers {
		peers = append(peers, p)
	}
	m.peers = make(map[string]*PeerConnection)
	m.peersMu.Unlock()

	for _, p := range peers {
		p.Close()
	}
}
