package main

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
)

// InboundGateway [Infrastructure Layer] bears the primary responsibility for running
// the embedded tailcat.Server instances (one per configured DERP region for primary/secondary
// availability), forwarding inbound peer connections to the local Python RPC port
// and any extra configured TCP ports (TAILCAT_SERVE_PORTS), and exposing SSH access
// (built-in Tailcat SSH or proxied local port 22) for remote standalone clients.
type InboundGateway struct {
	Vault                 *IdentityVault
	ServerKeyPath         string
	LocalPort             uint16
	ServePortsSpec        string
	AddrFile              string
	SSHMode               string
	SSHAuthorizedKeysSpec string
	AllowedClientsSpec    string
	Logf                  logger.Logf

	servers    []*tailcat.Server
	listenAddr tailcat.Addr
}

// NewInboundGateway constructs an InboundGateway for the specified local port, server key, and SSH settings.
func NewInboundGateway(vault *IdentityVault, serverKeyPath string, localPort uint16, addrFile string, logf logger.Logf) *InboundGateway {
	if logf == nil {
		logf = logger.Discard
	}
	return &InboundGateway{
		Vault:                 vault,
		ServerKeyPath:         serverKeyPath,
		LocalPort:             localPort,
		ServePortsSpec:        resolveServePortsSpec(serverKeyPath),
		AddrFile:              cmp.Or(addrFile, os.Getenv("TAILCAT_ADDR_FILE")),
		SSHMode:               cmp.Or(os.Getenv("TAILCAT_SSH_MODE"), "builtin"),
		SSHAuthorizedKeysSpec: os.Getenv("TAILCAT_SSH_AUTHORIZED_KEYS"),
		AllowedClientsSpec:    os.Getenv("TAILCAT_ALLOW_CLIENTS"),
		Logf:                  logf,
	}
}

func resolveServePortsSpec(serverKeyPath string) string {
	if envVal := strings.TrimSpace(os.Getenv("TAILCAT_SERVE_PORTS")); envVal != "" {
		return envVal
	}
	var candidates []string
	if strings.TrimSpace(serverKeyPath) != "" {
		meshDir := filepath.Dir(serverKeyPath)
		candidates = append(candidates, filepath.Join(filepath.Dir(meshDir), ".env"))
	}
	candidates = append(candidates, ".env", filepath.Join("..", ".env"))
	return readEnvValue("TAILCAT_SERVE_PORTS", candidates...)
}

func normalizeSSHMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "builtin", "built-in", "embedded", "tailcat":
		return "builtin"
	case "local", "native", "proxy", "sshd":
		return "local"
	case "off", "none", "false", "0", "disable", "disabled":
		return "off"
	default:
		return "builtin"
	}
}

// Start brings up the Tailcat WireGuard/DERP server listener and begins proxying inbound TCP flows
// addressed to LocalPort onto 127.0.0.1:<LocalPort>, as well as serving SSH on port 22 when enabled.
func (g *InboundGateway) Start(ctx context.Context) (tailcat.Addr, error) {
	conf, err := g.Vault.LoadServerKey(g.ServerKeyPath)
	if err != nil {
		return "", err
	}
	priv := conf.Private
	ci := &conf.Public
	psk := ci.PresharedKey
	usePSK := !psk.IsZero()
	embed := len(ci.Region) > 0

	if err := ci.Expand(ctx, tailcat.ExpandForServer, tailcat.DERPMapURL(g.Vault.DERPMapURL), g.Vault.Cache); err != nil {
		return "", fmt.Errorf("expand server DERP region: %w", err)
	}
	if len(ci.Region) == 0 {
		return "", fmt.Errorf("no DERP region resolved for server")
	}
	for _, r := range ci.Region {
		TrimDERPRegion(r)
	}

	addrCI := &tailcat.ConnInfo{
		ServerPublic:      tailcat.NodePublic{NodePublic: priv.Public()},
		ServerDiscoPublic: tailcat.DiscoPublicForNode(priv),
		PresharedKey:      psk,
	}
	if embed {
		addrCI.Region = ci.Region
	} else {
		addrCI.RegionID = ci.Region[0].RegionID
	}
	connStr := addrCI.Addr()

	allowedClients, err := g.Vault.LoadAllowedClientKeys(g.AllowedClientsSpec)
	if err != nil {
		return "", err
	}
	authKeys, err := g.Vault.ResolveSSHAuthorizedKeys(ctx, g.SSHAuthorizedKeysSpec, g.ServerKeyPath)
	if err != nil {
		return "", fmt.Errorf("load ssh authorized keys: %w", err)
	}

	sshMode := normalizeSSHMode(g.SSHMode)
	if sshMode == "builtin" && !tailcat.SupportsSSHServer() {
		g.Logf("built-in SSH server not supported on this platform; falling back to local port 22 proxy")
		sshMode = "local"
	}
	if sshMode == "builtin" && len(authKeys) == 0 && os.Getenv("TAILCAT_SSH_ALLOW_UNAUTHENTICATED") != "1" {
		fmt.Fprintf(os.Stderr, "[MeshBridge] ⚠️ built-in SSH server disabled (fail-closed): no authorized_keys configured in .mesh/authorized_keys or TAILCAT_SSH_AUTHORIZED_KEYS\n")
		sshMode = "off"
	}

	servedPorts, allowsExtraPort := parseServedPorts(g.LocalPort, sshMode, g.ServePortsSpec)

	localTarget := fmt.Sprintf("127.0.0.1:%d", g.LocalPort)
	localSSH := "127.0.0.1:22"
	localDialer := &net.Dialer{Timeout: 5 * time.Second}

	proxyToLocal := func(targetAddr string) func(net.Conn) {
		return func(remoteConn net.Conn) {
			localConn, err := localDialer.Dial("tcp", targetAddr)
			if err != nil {
				g.Logf("inbound proxy dial %s failed: %v", targetAddr, err)
				_ = remoteConn.Close()
				return
			}
			tailcat.ProxyConns(remoteConn, localConn)
		}
	}

	var startedServers []*tailcat.Server
	for _, reg := range ci.Region {
		srv := &tailcat.Server{
			Key:                 priv,
			PresharedKey:        psk,
			DisablePresharedKey: !usePSK,
			Logf:                g.Logf,
			Region:              reg,
			ServedTCPPorts:      servedPorts,
		}
		for _, k := range allowedClients {
			srv.AddAllowedClient(k)
		}

		var builtinSSHHandler func(net.Conn)
		if sshMode == "builtin" {
			builtinSSHHandler = srv.SSHConnHandler(tailcat.SSHOptions{
				Shell:          true,
				AuthorizedKeys: authKeys,
			})
		}

		srv.OnTCP = func(port uint16) func(net.Conn) {
			if port == g.LocalPort {
				return proxyToLocal(localTarget)
			}
			if port == 22 && sshMode != "off" {
				if builtinSSHHandler != nil {
					return builtinSSHHandler
				}
				return proxyToLocal(localSSH)
			}
			if allowsExtraPort(port) {
				return proxyToLocal(fmt.Sprintf("127.0.0.1:%d", port))
			}
			return nil
		}

		if err := srv.Start(); err != nil {
			for _, s := range startedServers {
				_ = s.Close()
			}
			return "", fmt.Errorf("tailcat.Server.Start (region %d): %w", reg.RegionID, err)
		}
		startedServers = append(startedServers, srv)
	}

	g.servers = startedServers
	g.listenAddr = connStr

	if g.AddrFile != "" {
		if tcpAddr, ok := strings.CutPrefix(g.AddrFile, "tcp:"); ok {
			if c, err := net.DialTimeout("tcp", tcpAddr, 3*time.Second); err == nil {
				_, _ = fmt.Fprintln(c, connStr)
				_ = c.Close()
			}
		} else {
			_ = os.WriteFile(g.AddrFile, []byte(string(connStr)+"\n"), 0600)
		}
	}

	return connStr, nil
}

// ListenAddr returns the active tailcat address (tc...) of this server.
func (g *InboundGateway) ListenAddr() tailcat.Addr {
	return g.listenAddr
}

// Close shuts down all underlying tailcat.Server instances.
func (g *InboundGateway) Close() error {
	var firstErr error
	for _, srv := range g.servers {
		if srv == nil {
			continue
		}
		if err := srv.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	g.servers = nil
	return firstErr
}

// parseServedPorts parses TAILCAT_SERVE_PORTS (comma-separated ports, port ranges like 8000-8010, or "all"/"*")
// and returns the combined filter.PortRange slice plus a matcher for extra proxied TCP ports.
func parseServedPorts(localPort uint16, sshMode string, extraSpec string) ([]filter.PortRange, func(uint16) bool) {
	served := []filter.PortRange{
		{First: localPort, Last: localPort},
	}
	if sshMode != "off" && localPort != 22 {
		served = []filter.PortRange{
			{First: 22, Last: 22},
			{First: localPort, Last: localPort},
		}
	}

	var extraRanges []filter.PortRange
	serveAll := false
	for _, token := range strings.Split(extraSpec, ",") {
		t := strings.ToLower(strings.TrimSpace(token))
		if t == "" {
			continue
		}
		if t == "all" || t == "*" {
			serveAll = true
			continue
		}
		if startStr, endStr, ok := strings.Cut(t, "-"); ok {
			startPort, err1 := strconv.ParseUint(strings.TrimSpace(startStr), 10, 16)
			endPort, err2 := strconv.ParseUint(strings.TrimSpace(endStr), 10, 16)
			if err1 == nil && err2 == nil && startPort > 0 && endPort >= startPort {
				extraRanges = append(extraRanges, filter.PortRange{
					First: uint16(startPort),
					Last:  uint16(endPort),
				})
			}
			continue
		}
		if p, err := strconv.ParseUint(t, 10, 16); err == nil && p > 0 {
			extraRanges = append(extraRanges, filter.PortRange{
				First: uint16(p),
				Last:  uint16(p),
			})
		}
	}

	if serveAll {
		return []filter.PortRange{{First: 1, Last: 65535}}, func(port uint16) bool {
			return port > 0
		}
	}

	served = append(served, extraRanges...)
	return served, func(port uint16) bool {
		for _, r := range extraRanges {
			if port >= r.First && port <= r.Last {
				return true
			}
		}
		return false
	}
}


