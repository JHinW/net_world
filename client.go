package main

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// StandaloneClient [Infrastructure Layer] bears the primary responsibility for running
// standalone client operations on a third machine: stdio TCP piping (connect),
// one-command OpenSSH client orchestration (ssh), and local TCP port forwarding (forward).
type StandaloneClient struct {
	Vault           *IdentityVault
	ClientKeyPath   string
	SSHIdentityFile string
	Logf            logger.Logf
}

// NewStandaloneClient constructs a StandaloneClient backed by IdentityVault.
func NewStandaloneClient(vault *IdentityVault, clientKeyPath string, logf logger.Logf) *StandaloneClient {
	if logf == nil {
		logf = logger.Discard
	}
	return &StandaloneClient{
		Vault:         vault,
		ClientKeyPath: clientKeyPath,
		Logf:          logf,
	}
}

func (c *StandaloneClient) loadClientKey() (key.NodePrivate, error) {
	priv, err := c.Vault.LoadClientKey(c.ClientKeyPath)
	if err != nil {
		return key.NodePrivate{}, fmt.Errorf("load client key: %w", err)
	}
	if priv.IsZero() {
		priv = key.NewNode()
	}
	return priv, nil
}

type writeCloserConn interface {
	CloseWrite() error
}

// ConnectStdio establishes a P2P WireGuard/DERP TCP connection to the target port (default 22)
// on rawAddr (trying candidate DERP regions in priority order with automatic failover)
// and bridges in/out with half-close propagation and TCP drain.
// It is designed to be invoked directly or via OpenSSH's `ProxyCommand`.
func (c *StandaloneClient) ConnectStdio(ctx context.Context, rawAddr string, optDest string, in io.Reader, out io.Writer) error {
	priv, err := c.loadClientKey()
	if err != nil {
		return err
	}

	target := strings.TrimSpace(optDest)
	if target == "" {
		target = "22"
	}

	var dialFn func(context.Context, *tailcat.Client) (net.Conn, error)
	if !strings.Contains(target, ":") {
		port, err := strconv.ParseUint(target, 10, 16)
		if err != nil || port == 0 {
			return fmt.Errorf("invalid port number %q", target)
		}
		dialFn = func(dctx context.Context, cl *tailcat.Client) (net.Conn, error) {
			return cl.DialTCPPort(dctx, uint16(port))
		}
	} else {
		addrPort, err := netip.ParseAddrPort(target)
		if err != nil || addrPort.Port() == 0 {
			return fmt.Errorf("invalid IP:port %q", target)
		}
		dialFn = func(dctx context.Context, cl *tailcat.Client) (net.Conn, error) {
			return cl.DialTCP(dctx, addrPort)
		}
	}

	cl, conn, _, err := c.Vault.DialWithFailover(ctx, rawAddr, priv, 15*time.Second, c.Logf, dialFn)
	if err != nil {
		return fmt.Errorf("dial tailcat remote %s: %w", target, err)
	}
	defer cl.Close()
	defer conn.Close()

	go func() {
		_, _ = io.Copy(conn, in)
		if wc, ok := conn.(writeCloserConn); ok {
			_ = wc.CloseWrite()
		}
	}()

	if _, err := io.Copy(out, conn); err != nil {
		return err
	}

	drainCtx, drainCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer drainCancel()
	_ = cl.DrainTCP(drainCtx)
	return nil
}

// ExecSSH orchestrates the host's native `ssh` client to connect to `[user@]<tc-addr>`
// over a self-invoked `mesh-bridge connect` ProxyCommand.
func (c *StandaloneClient) ExecSSH(portOrIPPort string, args []string) error {
	if len(args) == 0 {
		return errors.New("ssh requires a [user@]<tc-addr> destination argument")
	}
	canonicalPort, err := validateSSHPortSpec(cmp.Or(strings.TrimSpace(portOrIPPort), "22"))
	if err != nil {
		return err
	}

	dst := strings.TrimSpace(args[0])
	cmdArgs := args[1:]

	sshUser, addrStr, hasUser := strings.Cut(dst, "@")
	if !hasUser {
		addrStr = sshUser
		sshUser = ""
	}
	addrStr = strings.TrimSpace(addrStr)
	if _, err := c.Vault.ParseCandidateAddrs(addrStr); err != nil {
		return fmt.Errorf("invalid tailcat address %q: %w", addrStr, err)
	}

	selfExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	sshExe, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("no ssh client found in PATH: %w", err)
	}

	proxyCmd, err := c.buildSSHProxyCommand(selfExe, addrStr, canonicalPort)
	if err != nil {
		return err
	}

	sshHost := shortSSHDestHost(addrStr)
	if sshUser != "" {
		sshHost = sshUser + "@" + sshHost
	}

	var identityFile string
	if c.Vault != nil {
		identityFile = c.Vault.ResolveSSHIdentityFile(c.SSHIdentityFile, selfExe)
	} else {
		identityFile = strings.TrimSpace(c.SSHIdentityFile)
	}

	sshArgv := []string{
		"-o", "UpdateHostKeys=no",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=" + os.DevNull,
		"-o", "LogLevel=ERROR",
		"-o", "ProxyCommand=" + proxyCmd,
	}
	if strings.EqualFold(identityFile, "none") {
		sshArgv = append(sshArgv, "-o", "PubkeyAuthentication=no")
	} else if identityFile != "" {
		sshArgv = append(sshArgv, "-i", identityFile)
	}
	sshArgv = append(sshArgv, "--", sshHost)
	sshArgv = append(sshArgv, cmdArgs...)

	cmd := exec.Command(sshExe, sshArgv...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("run ssh: %w", err)
	}
	return nil
}

func (c *StandaloneClient) buildSSHProxyCommand(selfExe, addrStr, portOrIPPort string) (string, error) {
	argv := []string{selfExe}
	if strings.TrimSpace(c.ClientKeyPath) != "" {
		argv = append(argv, "--client-key="+c.ClientKeyPath)
	}
	if c.Vault != nil && c.Vault.DERPMapURL != "" && c.Vault.DERPMapURL != tailcat.DefaultDERPMapURL {
		argv = append(argv, "--derpmap-url="+c.Vault.DERPMapURL)
	}
	argv = append(argv, "connect", addrStr, portOrIPPort)
	if runtime.GOOS == "windows" {
		return joinProxyCommandWindows(argv)
	}
	return joinProxyCommandUnix(argv)
}

func validateSSHPortSpec(v string) (string, error) {
	if port, err := strconv.ParseUint(v, 10, 16); err == nil && port != 0 {
		return strconv.FormatUint(port, 10), nil
	}
	if ip, err := netip.ParseAddr(v); err == nil {
		return netip.AddrPortFrom(ip, 22).String(), nil
	}
	if ipPort, err := netip.ParseAddrPort(v); err == nil && ipPort.Port() != 0 {
		return ipPort.String(), nil
	}
	return "", fmt.Errorf("invalid port or IP:port %q", v)
}

func shortSSHDestHost(addr string) string {
	sum := sha256.Sum256([]byte(addr))
	return "tailcat-" + hex.EncodeToString(sum[:8])
}

func joinProxyCommandUnix(args []string) (string, error) {
	quoted := make([]string, len(args))
	for i, arg := range args {
		if strings.ContainsAny(arg, "\r\n\x00") {
			return "", fmt.Errorf("ProxyCommand argument contains control character: %q", arg)
		}
		arg = strings.ReplaceAll(arg, "%", "%%")
		quoted[i] = "'" + strings.ReplaceAll(arg, "'", `'"'"'`) + "'"
	}
	return strings.Join(quoted, " "), nil
}

func joinProxyCommandWindows(args []string) (string, error) {
	quoted := make([]string, len(args))
	for i, arg := range args {
		if strings.ContainsAny(arg, "\"%!\r\n\x00") {
			return "", fmt.Errorf("ProxyCommand argument contains unsafe character for cmd.exe: %q", arg)
		}
		var b strings.Builder
		b.WriteByte('"')
		b.WriteString(arg)
		b.WriteString(strings.Repeat("\\", len(arg)-len(strings.TrimRight(arg, "\\"))))
		b.WriteByte('"')
		quoted[i] = b.String()
	}
	return strings.Join(quoted, " "), nil
}

type forwardMapping struct {
	listenAddr string
	target     netip.AddrPort
	port       uint16
}

func (m forwardMapping) remoteLabel() string {
	if m.target.IsValid() {
		return m.target.String()
	}
	return net.JoinHostPort("localhost", strconv.Itoa(int(m.port)))
}

func parseForwardMapping(bindAddr, spec string) (forwardMapping, error) {
	bind := cmp.Or(strings.TrimSpace(bindAddr), "127.0.0.1")
	localPart, remotePart, hasColon := strings.Cut(strings.TrimSpace(spec), ":")
	if !hasColon {
		remotePart = localPart
	}
	var localPort uint16
	if !hasColon || localPart != "0" {
		p, err := strconv.ParseUint(localPart, 10, 16)
		if err != nil || p == 0 {
			return forwardMapping{}, fmt.Errorf("invalid local port %q", localPart)
		}
		localPort = uint16(p)
	}
	mapping := forwardMapping{
		listenAddr: net.JoinHostPort(bind, strconv.Itoa(int(localPort))),
	}
	if rp, err := strconv.ParseUint(remotePart, 10, 16); err == nil && rp > 0 {
		mapping.port = uint16(rp)
		return mapping, nil
	}
	if hasColon {
		if ap, err := netip.ParseAddrPort(remotePart); err == nil && ap.Port() > 0 {
			mapping.target = ap
			return mapping, nil
		}
	}
	return forwardMapping{}, fmt.Errorf("invalid remote target %q in mapping %q", remotePart, spec)
}

// ForwardPorts listens on one or more local TCP ports and forwards incoming connections
// to the remote tailcat peer (with primary-to-secondary DERP failover).
func (c *StandaloneClient) ForwardPorts(ctx context.Context, bindAddr string, rawAddr string, specs []string) error {
	if len(specs) == 0 {
		return errors.New("forward requires at least one <[local:]remote-port> mapping")
	}
	if _, err := c.Vault.ParseCandidateAddrs(rawAddr); err != nil {
		return err
	}
	priv, err := c.loadClientKey()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	var clientMu sync.Mutex
	var activeClient *tailcat.Client

	dialRemote := func(m forwardMapping) (net.Conn, error) {
		dialTarget := func(dctx context.Context, cl *tailcat.Client) (net.Conn, error) {
			if m.target.IsValid() {
				return cl.DialTCP(dctx, m.target)
			}
			return cl.DialTCPPort(dctx, m.port)
		}

		clientMu.Lock()
		cached := activeClient
		clientMu.Unlock()

		if cached != nil {
			warmCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
			conn, err := dialTarget(warmCtx, cached)
			cancel()
			if err == nil {
				return conn, nil
			}
		}

		clientMu.Lock()
		defer clientMu.Unlock()
		if activeClient != nil && activeClient != cached {
			warmCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
			conn, err := dialTarget(warmCtx, activeClient)
			cancel()
			if err == nil {
				return conn, nil
			}
		}
		if activeClient != nil {
			_ = activeClient.Close()
			activeClient = nil
		}
		cl, conn, _, err := c.Vault.DialWithFailover(ctx, rawAddr, priv, 15*time.Second, c.Logf, dialTarget)
		if err != nil {
			return nil, err
		}
		activeClient = cl
		return conn, nil
	}

	listeners := make([]net.Listener, 0, len(specs))
	var listenersWG, connsWG sync.WaitGroup
	var active sync.Map
	defer func() {
		stop()
		for _, ln := range listeners {
			_ = ln.Close()
		}
		listenersWG.Wait()
		active.Range(func(k, _ any) bool {
			_ = k.(net.Conn).Close()
			return true
		})
		connsWG.Wait()
		clientMu.Lock()
		if activeClient != nil {
			_ = activeClient.Close()
			activeClient = nil
		}
		clientMu.Unlock()
	}()

	for _, spec := range specs {
		mapping, err := parseForwardMapping(bindAddr, spec)
		if err != nil {
			return err
		}
		ln, err := net.Listen("tcp", mapping.listenAddr)
		if err != nil {
			return fmt.Errorf("listen on %s: %w", mapping.listenAddr, err)
		}
		listeners = append(listeners, ln)
		fmt.Fprintf(os.Stderr, "# forwarding %s -> remote %s\n", ln.Addr(), mapping.remoteLabel())

		listenersWG.Add(1)
		go func(ln net.Listener, m forwardMapping) {
			defer listenersWG.Done()
			for {
				localConn, err := ln.Accept()
				if err != nil {
					return
				}
				connsWG.Add(1)
				active.Store(localConn, struct{}{})
				go func() {
					defer connsWG.Done()
					defer active.Delete(localConn)
					defer localConn.Close()

					remoteConn, dialErr := dialRemote(m)
					if dialErr != nil {
						if ctx.Err() == nil {
							c.Logf("forward dial %s failed: %v", m.remoteLabel(), dialErr)
						}
						return
					}
					tailcat.ProxyConns(localConn, remoteConn)
				}()
			}
		}(ln, mapping)
	}

	<-ctx.Done()
	return nil
}

// RenderSSHConfigBlock generates a managed ~/.ssh/config Host block for VS Code Remote - SSH
// and OpenSSH clients. The full tailcat address is embedded into ProxyCommand so multi-region
// failover addresses work seamlessly without hitting hostname length limits.
func (c *StandaloneClient) RenderSSHConfigBlock(alias, dstSpec, portOrIPPort, selfExe string) (string, error) {
	alias = strings.TrimSpace(alias)
	if alias == "" || strings.ContainsAny(alias, " \t\r\n") {
		return "", fmt.Errorf("invalid SSH host alias %q", alias)
	}
	canonicalPort, err := validateSSHPortSpec(cmp.Or(strings.TrimSpace(portOrIPPort), "22"))
	if err != nil {
		return "", err
	}

	dst := strings.TrimSpace(dstSpec)
	sshUser, addrStr, hasUser := strings.Cut(dst, "@")
	if !hasUser {
		addrStr = sshUser
		sshUser = ""
	}
	addrStr = strings.TrimSpace(addrStr)
	if _, err := c.Vault.ParseCandidateAddrs(addrStr); err != nil {
		return "", fmt.Errorf("invalid tailcat address %q: %w", addrStr, err)
	}

	if strings.TrimSpace(selfExe) == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("resolve executable path: %w", err)
		}
		selfExe = exe
	}

	proxyCmd, err := c.buildSSHProxyCommand(selfExe, addrStr, canonicalPort)
	if err != nil {
		return "", err
	}

	var identityFile string
	if c.Vault != nil {
		identityFile = c.Vault.ResolveSSHIdentityFile(c.SSHIdentityFile, selfExe)
	} else {
		identityFile = strings.TrimSpace(c.SSHIdentityFile)
	}

	knownHostsNull := "/dev/null"
	if runtime.GOOS == "windows" {
		knownHostsNull = "NUL"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# BEGIN net_world:%s\n", alias)
	fmt.Fprintf(&b, "Host %s\n", alias)
	fmt.Fprintf(&b, "    HostName %s\n", shortSSHDestHost(addrStr))
	if sshUser != "" {
		fmt.Fprintf(&b, "    User %s\n", sshUser)
	}
	fmt.Fprintf(&b, "    ProxyCommand %s\n", proxyCmd)
	if strings.EqualFold(identityFile, "none") {
		fmt.Fprintf(&b, "    PubkeyAuthentication no\n")
	} else if identityFile != "" {
		fmt.Fprintf(&b, "    IdentityFile %s\n", quoteSSHConfigValue(identityFile))
	}
	fmt.Fprintf(&b, "    StrictHostKeyChecking no\n")
	fmt.Fprintf(&b, "    UserKnownHostsFile %s\n", knownHostsNull)
	fmt.Fprintf(&b, "    UpdateHostKeys no\n")
	fmt.Fprintf(&b, "    LogLevel ERROR\n")
	fmt.Fprintf(&b, "    ServerAliveInterval 30\n")
	fmt.Fprintf(&b, "    ServerAliveCountMax 3\n")
	fmt.Fprintf(&b, "# END net_world:%s\n", alias)
	return b.String(), nil
}

func quoteSSHConfigValue(v string) string {
	if strings.ContainsAny(v, " \t\"") {
		return `"` + strings.ReplaceAll(v, `"`, `\"`) + `"`
	}
	return v
}

// UpsertSSHConfigFile idempotently inserts or updates the managed Host block for alias
// in configPath (defaults to ~/.ssh/config when empty) and returns the resolved path.
func UpsertSSHConfigFile(configPath, alias, block string) (string, error) {
	resolvedPath := strings.TrimSpace(configPath)
	if resolvedPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve user home dir: %w", err)
		}
		resolvedPath = filepath.Join(home, ".ssh", "config")
	}
	if err := os.MkdirAll(filepath.Dir(resolvedPath), 0o700); err != nil {
		return "", fmt.Errorf("create ssh config dir: %w", err)
	}

	beginMarker := "# BEGIN net_world:" + alias
	endMarker := "# END net_world:" + alias
	normalizedBlock := strings.TrimRight(block, "\r\n") + "\n"

	existingBytes, err := os.ReadFile(resolvedPath)
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("read ssh config %s: %w", resolvedPath, err)
	}
	existing := strings.ReplaceAll(string(existingBytes), "\r\n", "\n")

	var updated string
	beginIdx := strings.Index(existing, beginMarker)
	endIdx := strings.Index(existing, endMarker)
	if beginIdx >= 0 && endIdx > beginIdx {
		afterEnd := endIdx + len(endMarker)
		if afterEnd < len(existing) && existing[afterEnd] == '\n' {
			afterEnd++
		}
		updated = existing[:beginIdx] + normalizedBlock + existing[afterEnd:]
	} else {
		trimmed := strings.TrimRight(existing, "\n")
		if trimmed == "" {
			updated = normalizedBlock
		} else {
			updated = trimmed + "\n\n" + normalizedBlock
		}
	}

	if err := os.WriteFile(resolvedPath, []byte(updated), 0o600); err != nil {
		return "", fmt.Errorf("write ssh config %s: %w", resolvedPath, err)
	}
	return resolvedPath, nil
}

// ExecSSHConfig renders the SSH config block for VS Code Remote - SSH and optionally
// writes it to ~/.ssh/config (or configPath) when writeToFile is true.
func (c *StandaloneClient) ExecSSHConfig(portOrIPPort, configPath string, writeToFile bool, args []string) error {
	alias, dstSpec, err := parseAliasAndTargetArgs("ssh-config", args)
	if err != nil {
		return err
	}
	block, err := c.RenderSSHConfigBlock(alias, dstSpec, portOrIPPort, "")
	if err != nil {
		return err
	}
	if !writeToFile {
		fmt.Print(block)
		return nil
	}
	writtenPath, err := UpsertSSHConfigFile(configPath, alias, block)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "# Updated SSH host %q in %s\n", alias, writtenPath)
	fmt.Print(block)
	return nil
}

// ExecVSCode updates the managed SSH host entry in ~/.ssh/config (or configPath)
// and launches the local VS Code client connected to `ssh-remote+<alias>`.
func (c *StandaloneClient) ExecVSCode(portOrIPPort, configPath string, args []string) error {
	alias, dstSpec, err := parseAliasAndTargetArgs("vscode", args)
	if err != nil {
		return err
	}
	remotePath := ""
	if len(args) >= 3 {
		remotePath = strings.TrimSpace(args[2])
	}
	block, err := c.RenderSSHConfigBlock(alias, dstSpec, portOrIPPort, "")
	if err != nil {
		return err
	}
	writtenPath, err := UpsertSSHConfigFile(configPath, alias, block)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "# Configured SSH host %q in %s\n", alias, writtenPath)

	codeExe, err := findVSCodeExecutable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "# VS Code CLI ('code') not found in PATH. Connect manually in VS Code Remote-SSH to host: %s\n", alias)
		return nil
	}

	codeArgs := []string{"--remote", "ssh-remote+" + alias}
	if remotePath != "" {
		codeArgs = append(codeArgs, remotePath)
	} else {
		codeArgs = append([]string{"--new-window"}, codeArgs...)
	}

	cmd := exec.Command(codeExe, codeArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("launch vscode (%s %s): %w", codeExe, strings.Join(codeArgs, " "), err)
	}
	return nil
}

func parseAliasAndTargetArgs(subcmd string, args []string) (alias string, dstSpec string, err error) {
	if len(args) == 1 {
		return "networld-remote", args[0], nil
	}
	if len(args) >= 2 {
		return args[0], args[1], nil
	}
	return "", "", fmt.Errorf("%s requires [<alias>] [user@]<tc-addr>", subcmd)
}

func findVSCodeExecutable() (string, error) {
	for _, bin := range []string{"code", "code-insiders", "cursor"} {
		if p, err := exec.LookPath(bin); err == nil {
			return p, nil
		}
	}
	if runtime.GOOS == "darwin" {
		macCandidates := []string{
			"/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code",
			"/Applications/Visual Studio Code - Insiders.app/Contents/Resources/app/bin/code",
			"/Applications/Cursor.app/Contents/Resources/app/bin/cursor",
		}
		for _, p := range macCandidates {
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
		}
	}
	return "", errors.New("vscode CLI not found")
}

