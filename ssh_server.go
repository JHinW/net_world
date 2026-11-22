package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/pkg/sftp"
	ssh "github.com/tailscale/gliderssh"
	gossh "golang.org/x/crypto/ssh"
	"tailscale.com/types/logger"
)

const builtinSSHInteractiveMOTD = "🐈 Connected via MeshBridge built-in SSH (VS Code Remote ready).\r\n"

// newBuiltinSSHHandler returns a connection handler for inbound port 22 that
// serves an embedded SSH server with full VS Code Remote - SSH capabilities:
//   - interactive PTY shell & non-interactive command execution ("session")
//   - local TCP port forwarding ("direct-tcpip", i.e. `ssh -L`)
//   - remote TCP port forwarding ("tcpip-forward", i.e. `ssh -R`)
//   - local & remote Unix domain socket forwarding ("direct-streamlocal@openssh.com", "streamlocal-forward@openssh.com")
//   - SFTP subsystem ("sftp")
//   - SSH agent forwarding ("auth-agent-req@openssh.com")
func newBuiltinSSHHandler(authKeys []string, logf logger.Logf) func(net.Conn) {
	if logf == nil {
		logf = logger.Discard
	}
	pubKeyHandler, authErr := buildSSHPublicKeyHandler(authKeys)

	return func(c net.Conn) {
		if authErr != nil {
			logf("builtin ssh authorized_keys error: %v", authErr)
			_ = c.Close()
			return
		}
		hostSigners, err := getOrCreateSSHHostKeys()
		if err != nil {
			logf("builtin ssh host keys error: %v", err)
			_ = c.Close()
			return
		}

		fwdTCP := &ssh.ForwardedTCPHandler{}
		fwdUnix := &ssh.ForwardedUnixHandler{}

		srv := &ssh.Server{
			Handler:          handleSSHSession,
			PublicKeyHandler: pubKeyHandler,
			PtyCallback: func(_ ssh.Context, _ ssh.Pty) bool {
				return true
			},
			SessionRequestCallback: func(_ ssh.Session, _ string) bool {
				return true
			},
			LocalPortForwardingCallback: func(_ ssh.Context, _ string, _ uint32) bool {
				return true
			},
			ReversePortForwardingCallback: func(_ ssh.Context, _ string, _ uint32) bool {
				return true
			},
			LocalUnixForwardingCallback: ssh.NewLocalUnixForwardingCallback(ssh.UnixForwardingOptions{
				AllowAll: true,
			}),
			ReverseUnixForwardingCallback: ssh.NewReverseUnixForwardingCallback(ssh.UnixForwardingOptions{
				AllowAll:   true,
				BindUnlink: true,
			}),
			ChannelHandlers: map[string]ssh.ChannelHandler{
				"session":                        ssh.DefaultSessionHandler,
				"direct-tcpip":                   ssh.DirectTCPIPHandler,
				"direct-streamlocal@openssh.com": ssh.DirectStreamLocalHandler,
			},
			RequestHandlers: map[string]ssh.RequestHandler{
				"tcpip-forward":                          fwdTCP.HandleSSHRequest,
				"cancel-tcpip-forward":                   fwdTCP.HandleSSHRequest,
				"streamlocal-forward@openssh.com":        fwdUnix.HandleSSHRequest,
				"cancel-streamlocal-forward@openssh.com": fwdUnix.HandleSSHRequest,
			},
			SubsystemHandlers: map[string]ssh.SubsystemHandler{
				"sftp": handleSFTPSubsystem(logf),
			},
		}
		if pubKeyHandler == nil {
			srv.NoClientAuthHandler = func(_ ssh.Context) error { return nil }
		}
		for _, signer := range hostSigners {
			srv.AddHostKey(signer)
		}
		srv.HandleConn(c)
	}
}

func handleSFTPSubsystem(logf logger.Logf) ssh.SubsystemHandler {
	return func(sess ssh.Session) {
		var opts []sftp.ServerOption
		// pkg/sftp uses path.IsAbs (POSIX) before toLocalPath, so setting workDir
		// on Windows causes drive-letter paths like C:\... to be joined onto workDir.
		if runtime.GOOS != "windows" {
			if home, err := os.UserHomeDir(); err == nil && home != "" {
				opts = append(opts, sftp.WithServerWorkingDirectory(home))
			}
		}
		srv, err := sftp.NewServer(sess, opts...)
		if err != nil {
			logf("sftp init error: %v", err)
			_ = sess.Exit(1)
			return
		}
		err = srv.Serve()
		if errors.Is(err, io.EOF) {
			err = nil
		}
		if err != nil {
			logf("sftp serve error: %v", err)
			_ = sess.Exit(1)
		} else {
			_ = sess.Exit(0)
		}
		_ = srv.Close()
	}
}

func handleSSHSession(sess ssh.Session) {
	u, err := user.Current()
	if err != nil {
		_, _ = fmt.Fprintf(sess.Stderr(), "failed to resolve current user: %v\r\n", err)
		_ = sess.Exit(1)
		return
	}

	cmd := newPlatformSessionCommand(u, sess.RawCommand())
	for _, kv := range sess.Environ() {
		if acceptSSHEnvPair(kv) {
			cmd.Env = append(cmd.Env, kv)
		}
	}

	if ssh.AgentRequested(sess) {
		if agentLn, err := ssh.NewAgentListener(); err == nil {
			defer func() {
				_ = agentLn.Close()
				_ = os.RemoveAll(filepath.Dir(agentLn.Addr().String()))
			}()
			go ssh.ForwardAgentConnections(agentLn, sess)
			cmd.Env = append(cmd.Env, "SSH_AUTH_SOCK="+agentLn.Addr().String())
		}
	}

	ptyReq, winCh, isPTY := sess.Pty()
	if isPTY && sess.RawCommand() == "" {
		_, _ = io.WriteString(sess, builtinSSHInteractiveMOTD)
	}
	if isPTY {
		sess.DisablePTYEmulation()
		runSessionWithPTY(sess, cmd, ptyReq, winCh)
		return
	}
	runSessionWithPipes(sess, cmd)
}

func runSessionWithPipes(sess ssh.Session, cmd *exec.Cmd) {
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		_, _ = fmt.Fprintf(sess.Stderr(), "stdin pipe: %v\r\n", err)
		_ = sess.Exit(1)
		return
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		_, _ = fmt.Fprintf(sess.Stderr(), "stdout pipe: %v\r\n", err)
		_ = sess.Exit(1)
		return
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		_, _ = fmt.Fprintf(sess.Stderr(), "stderr pipe: %v\r\n", err)
		_ = sess.Exit(1)
		return
	}

	if err := cmd.Start(); err != nil {
		_, _ = fmt.Fprintf(sess.Stderr(), "start: %v\r\n", err)
		_ = sess.Exit(1)
		return
	}

	go func() {
		defer stdinPipe.Close()
		_, _ = io.Copy(stdinPipe, sess)
	}()

	outputDone := make(chan struct{})
	var openStreams atomic.Int32
	openStreams.Store(2)
	closeStream := func() {
		if openStreams.Add(-1) == 0 {
			close(outputDone)
		}
	}
	go func() {
		defer closeStream()
		_, _ = io.Copy(sess, stdoutPipe)
	}()
	go func() {
		defer closeStream()
		_, _ = io.Copy(sess.Stderr(), stderrPipe)
	}()

	<-outputDone
	if err := cmd.Wait(); err != nil {
		_ = sess.Exit(processExitCode(err))
		return
	}
	_ = sess.Exit(0)
}

func processExitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 1
}

func acceptSSHEnvPair(kv string) bool {
	k, _, ok := strings.Cut(kv, "=")
	if !ok {
		return false
	}
	return k == "TERM" ||
		k == "COLORTERM" ||
		k == "LANG" ||
		strings.HasPrefix(k, "LC_") ||
		strings.HasPrefix(k, "VSCODE_")
}

func buildSSHPublicKeyHandler(texts []string) (ssh.PublicKeyHandler, error) {
	if len(texts) == 0 {
		return nil, nil
	}
	allowed := make(map[string]bool)
	for textIdx, text := range texts {
		for lineIdx, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			pubKey, _, _, rest, err := gossh.ParseAuthorizedKey([]byte(line))
			if err != nil || len(bytes.TrimSpace(rest)) != 0 {
				if err == nil {
					err = errors.New("unexpected trailing data")
				}
				return nil, fmt.Errorf("authorized_keys source %d line %d: %w", textIdx+1, lineIdx+1, err)
			}
			allowed[string(pubKey.Marshal())] = true
		}
	}
	if len(allowed) == 0 {
		return nil, errors.New("no valid SSH public keys found")
	}
	return func(_ ssh.Context, key ssh.PublicKey) error {
		if allowed[string(key.Marshal())] {
			return nil
		}
		return errors.New("SSH public key is not authorized")
	}, nil
}

var builtinHostKeyMu sync.Mutex

func getOrCreateSSHHostKeys() ([]gossh.Signer, error) {
	builtinHostKeyMu.Lock()
	defer builtinHostKeyMu.Unlock()

	cfgDir, err := os.UserConfigDir()
	if err != nil {
		cfgDir = os.TempDir()
	}
	keyDir := filepath.Join(cfgDir, "tailcat", "ssh")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(keyDir, "ssh_host_ed25519_key")
	pemData, err := os.ReadFile(keyPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		pemData = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
		if err := os.WriteFile(keyPath, pemData, 0o600); err != nil {
			return nil, err
		}
	}
	signer, err := gossh.ParsePrivateKey(pemData)
	if err != nil {
		return nil, fmt.Errorf("parse ssh host key: %w", err)
	}
	return []gossh.Signer{signer}, nil
}
