package main

import (
	"cmp"
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"tailscale.com/types/logger"
)

// BridgeApp [Application Layer] orchestrates IdentityVault, InboundGateway, OutboundMultiplexer,
// and StandaloneClient to run the unified single-process Tailcat Mesh gateway or execute standalone client subcommands.
type BridgeApp struct {
	Vault                 *IdentityVault
	ServerKeyPath         string
	ClientKeyPath         string
	SSHIdentityFile       string
	ServePortsSpec        string
	AddrFile              string
	SSHMode               string
	SSHAuthorizedKeysSpec string
	AllowedClientsSpec    string
	Verbose               bool
}

func (a *BridgeApp) logf() logger.Logf {
	if a.Verbose {
		return log.Printf
	}
	return logger.Discard
}

func (a *BridgeApp) standaloneClient() *StandaloneClient {
	clientKey := a.ClientKeyPath
	if clientKey == "" {
		clientKey = a.ServerKeyPath
	}
	sc := NewStandaloneClient(a.Vault, clientKey, a.logf())
	sc.SSHIdentityFile = a.SSHIdentityFile
	return sc
}

// RunBridge starts the unified single-process daemon:
// 1. Starts InboundGateway (*tailcat.Server) in the background to accept peer connections (port <localPort> + SSH port 22 + TAILCAT_SERVE_PORTS);
// 2. Runs OutboundMultiplexer on stdin/stdout to multiplex outbound peer connections in-memory;
// 3. Automatically terminates when stdin closes (parent process exit) or on SIGINT/SIGTERM.
func (a *BridgeApp) RunBridge(ctx context.Context, localPort uint16) error {
	inbound := NewInboundGateway(a.Vault, a.ServerKeyPath, localPort, a.AddrFile, a.logf())
	if a.ServePortsSpec != "" {
		inbound.ServePortsSpec = a.ServePortsSpec
	}
	if a.SSHMode != "" {
		inbound.SSHMode = a.SSHMode
	}
	if a.SSHAuthorizedKeysSpec != "" {
		inbound.SSHAuthorizedKeysSpec = a.SSHAuthorizedKeysSpec
	}
	if a.AllowedClientsSpec != "" {
		inbound.AllowedClientsSpec = a.AllowedClientsSpec
	}
	go func() {
		backoff := 2 * time.Second
		const maxBackoff = 15 * time.Second
		for attempt := 1; ; attempt++ {
			addr, err := inbound.Start(ctx)
			if err == nil {
				fmt.Fprintf(os.Stderr, "# 🐈 MeshBridge unified server listening on port %d (ssh=%s): %s\n", localPort, normalizeSSHMode(inbound.SSHMode), addr)
				return
			}
			if ctx.Err() != nil {
				return
			}
			fmt.Fprintf(os.Stderr, "[MeshBridge] inbound server start error (attempt %d, retrying in %s): %v\n", attempt, backoff, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}()
	defer inbound.Close()

	clientPriv, err := a.Vault.LoadClientKey(a.ClientKeyPath)
	if err != nil {
		return fmt.Errorf("load client key: %w", err)
	}

	mux := NewOutboundMultiplexer(a.Vault, clientPriv, os.Stdout, a.logf())
	defer mux.CloseAll()

	done := make(chan struct{})
	go func() {
		mux.ServeStdio(os.Stdin)
		close(done)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case <-done:
		return nil
	case <-sigCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func parsePortArg(raw string, defaultPort uint16) uint16 {
	s := strings.TrimSpace(raw)
	if s == "" {
		return defaultPort
	}
	if idx := strings.IndexByte(s, ','); idx >= 0 {
		s = s[:idx]
	}
	p, err := strconv.ParseUint(s, 10, 16)
	if err != nil || p == 0 {
		return defaultPort
	}
	return uint16(p)
}

func printUsage() {
	fmt.Println(`Usage:
  mesh-bridge [flags] [bridge [port]]
  mesh-bridge [flags] ssh [-p <port>] [user@]<tc-addr> [command [args...]]
  mesh-bridge [flags] ssh-config [--write] [--ssh-config=<path>] [<alias>] [user@]<tc-addr>
  mesh-bridge [flags] vscode [--ssh-config=<path>] [<alias>] [user@]<tc-addr> [remote-path]
  mesh-bridge [flags] connect <tc-addr> [port|ip:port]
  mesh-bridge [flags] forward [--bind=127.0.0.1] <tc-addr> <[local:]remote-port> [...]
  mesh-bridge [flags] genkey [--client] [--fixed-region] [--force]
  mesh-bridge [flags] parse <tc-addr>

Flags:
  --env-file=<path>                  Load environment variables from a custom .env file
  --key=<path|name>                  Server key path or name (also used as client key fallback)
  --client-key=<path|name>           Client identity key path or name
  --addr-file=<path|tcp:host:port>   Write active server tailcat address to file or TCP endpoint
  --serve-ports=<ports|range|all>    Extra local TCP ports to expose (or via TAILCAT_SERVE_PORTS)
  --ssh-mode=<builtin|local|off>     Inbound SSH server mode on port 22 (default: builtin)
  --ssh-authorized-keys=<sources>    Comma-separated authorized_keys paths, pubkeys, or user@github
  --allow=<nodekeys>                 Comma-separated allowed client node public keys (nodekey:...)
  --derpmap-url=<url>                Custom DERP map URL
  --bind=<ip>                        Local bind address for 'forward' (default: 127.0.0.1)
  -p, --port=<port|ip:port>          Remote SSH port for 'ssh'/'ssh-config'/'vscode' (default: 22)
  -i, --identity=<ssh-private-key>   SSH private key file for 'ssh'/'ssh-config'/'vscode'
  -w, --write                        Write generated Host block into ~/.ssh/config (for 'ssh-config')
  --ssh-config=<path>                Custom SSH config file path (default: ~/.ssh/config)
  -v, --verbose                      Enable verbose logging`)
}

func main() {
	var (
		envFileFlag       string
		keyFlag           string
		clientKeyFlag     string
		sshIdentityFlag   string
		servePortsFlag    string
		addrFileFlag      string
		derpMapURL        string
		sshModeFlag       string
		sshAuthKeysFlag   string
		allowClientsFlag  string
		bindAddrFlag      string
		sshPortFlag       string
		sshConfigPathFlag string
		writeConfigFlag   bool
		verbose           bool
		fixedRegion       bool
		clientModeKey     bool
		forceFlag         bool
		positional        []string
	)

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		// Once in `ssh` subcommand and target `[user@]<tc-addr>` is already collected,
		// pass all remaining arguments verbatim as the remote command.
		if len(positional) >= 2 && positional[0] == "ssh" {
			positional = append(positional, os.Args[i:]...)
			break
		}
		if arg == "--" {
			positional = append(positional, os.Args[i+1:]...)
			break
		}

		switch {
		case strings.HasPrefix(arg, "--env-file="):
			envFileFlag = strings.TrimPrefix(arg, "--env-file=")
		case arg == "--env-file" && i+1 < len(os.Args):
			i++
			envFileFlag = os.Args[i]
		case strings.HasPrefix(arg, "--key="):
			keyFlag = strings.TrimPrefix(arg, "--key=")
		case arg == "--key" && i+1 < len(os.Args):
			i++
			keyFlag = os.Args[i]
		case strings.HasPrefix(arg, "--client-key="):
			clientKeyFlag = strings.TrimPrefix(arg, "--client-key=")
		case arg == "--client-key" && i+1 < len(os.Args):
			i++
			clientKeyFlag = os.Args[i]
		case strings.HasPrefix(arg, "--addr-file="):
			addrFileFlag = strings.TrimPrefix(arg, "--addr-file=")
		case strings.HasPrefix(arg, "--serve-ports="):
			servePortsFlag = strings.TrimPrefix(arg, "--serve-ports=")
		case arg == "--serve-ports" && i+1 < len(os.Args):
			i++
			servePortsFlag = os.Args[i]
		case strings.HasPrefix(arg, "--derpmap-url="):
			derpMapURL = strings.TrimPrefix(arg, "--derpmap-url=")
		case strings.HasPrefix(arg, "--ssh-mode="):
			sshModeFlag = strings.TrimPrefix(arg, "--ssh-mode=")
		case arg == "--ssh-mode" && i+1 < len(os.Args):
			i++
			sshModeFlag = os.Args[i]
		case strings.HasPrefix(arg, "--ssh-authorized-keys="):
			sshAuthKeysFlag = strings.TrimPrefix(arg, "--ssh-authorized-keys=")
		case arg == "--ssh-authorized-keys" && i+1 < len(os.Args):
			i++
			sshAuthKeysFlag = os.Args[i]
		case strings.HasPrefix(arg, "--allow="):
			allowClientsFlag = strings.TrimPrefix(arg, "--allow=")
		case arg == "--allow" && i+1 < len(os.Args):
			i++
			allowClientsFlag = os.Args[i]
		case strings.HasPrefix(arg, "--bind="):
			bindAddrFlag = strings.TrimPrefix(arg, "--bind=")
		case arg == "--bind" && i+1 < len(os.Args):
			i++
			bindAddrFlag = os.Args[i]
		case strings.HasPrefix(arg, "--port="):
			sshPortFlag = strings.TrimPrefix(arg, "--port=")
		case (arg == "-p" || arg == "--port") && i+1 < len(os.Args):
			i++
			sshPortFlag = os.Args[i]
		case strings.HasPrefix(arg, "--identity="):
			sshIdentityFlag = strings.TrimPrefix(arg, "--identity=")
		case strings.HasPrefix(arg, "-i="):
			sshIdentityFlag = strings.TrimPrefix(arg, "-i=")
		case (arg == "-i" || arg == "--identity") && i+1 < len(os.Args):
			i++
			sshIdentityFlag = os.Args[i]
		case strings.HasPrefix(arg, "--ssh-config="):
			sshConfigPathFlag = strings.TrimPrefix(arg, "--ssh-config=")
		case arg == "--ssh-config" && i+1 < len(os.Args):
			i++
			sshConfigPathFlag = os.Args[i]
		case arg == "--write" || arg == "-w":
			writeConfigFlag = true
		case arg == "--verbose" || arg == "-v":
			verbose = true
		case arg == "--fixed-region":
			fixedRegion = true
		case arg == "--client":
			clientModeKey = true
		case arg == "--force" || arg == "-f":
			forceFlag = true
		case arg == "--help" || arg == "-h" || arg == "help":
			printUsage()
			return
		case arg == "version" || arg == "--version":
			fmt.Println("v0.7.0-mesh-bridge")
			return
		default:
			if !strings.HasPrefix(arg, "-") {
				positional = append(positional, arg)
			}
		}
	}

	if envPath := cmp.Or(envFileFlag, os.Getenv("TAILCAT_ENV_FILE")); envPath != "" {
		if err := loadEnvFile(envPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	keyFlag = cmp.Or(keyFlag, os.Getenv("TAILCAT_KEY"))
	clientKeyFlag = cmp.Or(clientKeyFlag, os.Getenv("TAILCAT_CLIENT_KEY"))
	if !verbose {
		envVerbose := strings.TrimSpace(os.Getenv("TAILCAT_VERBOSE"))
		verbose = envVerbose == "1" || strings.EqualFold(envVerbose, "true")
	}

	vault := NewIdentityVault(derpMapURL)
	app := &BridgeApp{
		Vault:                 vault,
		ServerKeyPath:         keyFlag,
		ClientKeyPath:         clientKeyFlag,
		SSHIdentityFile:       sshIdentityFlag,
		ServePortsSpec:        servePortsFlag,
		AddrFile:              addrFileFlag,
		SSHMode:               sshModeFlag,
		SSHAuthorizedKeysSpec: sshAuthKeysFlag,
		AllowedClientsSpec:    allowClientsFlag,
		Verbose:               verbose,
	}

	defaultBridgePort := parsePortArg(os.Getenv("TAILCAT_BRIDGE_PORT"), 19100)

	if len(positional) == 0 {
		if err := app.RunBridge(context.Background(), defaultBridgePort); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	subcmd := positional[0]
	rest := positional[1:]

	switch subcmd {
	case "bridge":
		port := defaultBridgePort
		if len(rest) > 0 {
			port = parsePortArg(rest[0], defaultBridgePort)
		}
		if err := app.RunBridge(context.Background(), port); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

	case "ssh":
		if err := app.standaloneClient().ExecSSH(sshPortFlag, rest); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

	case "ssh-config":
		if err := app.standaloneClient().ExecSSHConfig(sshPortFlag, sshConfigPathFlag, writeConfigFlag, rest); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

	case "vscode":
		if err := app.standaloneClient().ExecVSCode(sshPortFlag, sshConfigPathFlag, rest); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

	case "connect":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "connect requires <tc-addr> [port|ip:port]")
			os.Exit(1)
		}
		targetPort := "22"
		if len(rest) > 1 {
			targetPort = rest[1]
		}
		if err := app.standaloneClient().ConnectStdio(context.Background(), rest[0], targetPort, os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

	case "forward":
		if len(rest) < 2 {
			fmt.Fprintln(os.Stderr, "forward requires <tc-addr> and at least one <[local:]remote-port> mapping")
			os.Exit(1)
		}
		if err := app.standaloneClient().ForwardPorts(context.Background(), bindAddrFlag, rest[0], rest[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

	case "genkey":
		if clientModeKey {
			targetKey := clientKeyFlag
			if targetKey == "" {
				targetKey = keyFlag
			}
			pub, err := vault.GenerateClientKey(targetKey, forceFlag)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println(pub)
			return
		}
		addr, err := vault.GenerateServerKey(context.Background(), keyFlag, fixedRegion, forceFlag)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(addr)

	case "parse":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "parse requires one <tc-addr> argument")
			os.Exit(1)
		}
		out, err := vault.ParseAddressJSON(rest[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(string(out))

	default:
		// Allow `mesh-bridge <tc-addr> [port]` as a direct shorthand for `mesh-bridge connect <tc-addr> [port]`
		if strings.HasPrefix(subcmd, "tc") {
			targetPort := "22"
			if len(rest) > 0 {
				targetPort = rest[0]
			}
			if err := app.standaloneClient().ConnectStdio(context.Background(), subcmd, targetPort, os.Stdin, os.Stdout); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		}
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", subcmd)
		os.Exit(1)
	}
}

