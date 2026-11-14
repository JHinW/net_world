package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/tailscale/tailcat"
	gossh "golang.org/x/crypto/ssh"
	"tailscale.com/tailcfg"
)

func TestIdentityVaultKeyGenerationAndRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	vault := NewIdentityVault("")

	// 1. Generate client key and reload
	clientKeyPath := filepath.Join(tmp, "node-a.client.private.json")
	pubStr, err := vault.GenerateClientKey(clientKeyPath, true)
	if err != nil {
		t.Fatalf("GenerateClientKey failed: %v", err)
	}
	if !strings.HasPrefix(pubStr, "nodekey:") {
		t.Fatalf("unexpected client public key format: %s", pubStr)
	}

	loadedClient, err := vault.LoadClientKey(clientKeyPath)
	if err != nil {
		t.Fatalf("LoadClientKey failed: %v", err)
	}
	if loadedClient.Public().String() != pubStr {
		t.Fatalf("client public key mismatch: got %s, want %s", loadedClient.Public().String(), pubStr)
	}

	// 2. Generate server key (without network probe: fixedRegion=false) and reload
	serverKeyPath := filepath.Join(tmp, "node-a.private.json")
	tcAddr, err := vault.GenerateServerKey(t.Context(), serverKeyPath, false, true)
	if err != nil {
		t.Fatalf("GenerateServerKey failed: %v", err)
	}
	if !strings.HasPrefix(string(tcAddr), "tc") {
		t.Fatalf("unexpected tailcat addr format: %s", tcAddr)
	}

	loadedServer, err := vault.LoadServerKey(serverKeyPath)
	if err != nil {
		t.Fatalf("LoadServerKey failed: %v", err)
	}
	if loadedServer.Public.Addr() != tcAddr {
		t.Fatalf("server addr mismatch: got %s, want %s", loadedServer.Public.Addr(), tcAddr)
	}

	// 3. ParseAddrJSON round-trip
	parsedBytes, err := vault.ParseAddressJSON(string(tcAddr))
	if err != nil {
		t.Fatalf("ParseAddressJSON failed: %v", err)
	}
	var parsedMap map[string]any
	if err := json.Unmarshal(parsedBytes, &parsedMap); err != nil {
		t.Fatalf("Unmarshal parsed address JSON failed: %v", err)
	}
	if parsedMap["ServerPublic"] == nil {
		t.Fatalf("expected ServerPublic in parsed JSON: %s", string(parsedBytes))
	}
}

func TestOutboundMultiplexerMissingAddrReturnsErrorWithMuxID(t *testing.T) {
	vault := NewIdentityVault("")
	clientKey, _ := vault.LoadClientKey("new")
	var outBuf bytes.Buffer
	mux := NewOutboundMultiplexer(vault, clientKey, &outBuf, nil)

	in := strings.NewReader(`{"mux_id":"m-42","op":"ping","tc_addr":""}` + "\n")
	mux.ServeStdio(in)

	// Wait briefly for the spawned goroutine to emit
	for range 50 {
		if outBuf.Len() > 0 {
			break
		}
	}
	line := strings.TrimSpace(outBuf.String())
	if line == "" {
		t.Fatal("expected error JSON line from multiplexer")
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if resp["mux_id"] != "m-42" || resp["type"] != "error" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestSSHModeAndKeyValidation(t *testing.T) {
	if got := normalizeSSHMode(""); got != "builtin" {
		t.Fatalf("expected default builtin, got %s", got)
	}
	if got := normalizeSSHMode("local"); got != "local" {
		t.Fatalf("expected local, got %s", got)
	}
	if got := normalizeSSHMode("off"); got != "off" {
		t.Fatalf("expected off, got %s", got)
	}

	vault := NewIdentityVault("")
	tmp := t.TempDir()
	clientKeyPath := filepath.Join(tmp, "c1.client.private.json")
	pubStr, err := vault.GenerateClientKey(clientKeyPath, true)
	if err != nil {
		t.Fatalf("GenerateClientKey: %v", err)
	}

	allowed, err := vault.LoadAllowedClientKeys(pubStr + ", none")
	if err != nil {
		t.Fatalf("LoadAllowedClientKeys failed: %v", err)
	}
	if len(allowed) != 2 || allowed[0].String() != pubStr || !allowed[1].IsZero() {
		t.Fatalf("unexpected allowed client keys: %+v", allowed)
	}

	validSSHKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@mesh"
	keys, err := vault.LoadSSHAuthorizedKeys(t.Context(), validSSHKey)
	if err != nil || len(keys) != 1 {
		t.Fatalf("LoadSSHAuthorizedKeys failed: err=%v, keys=%v", err, keys)
	}

	// Verify auto-discovery of authorized_keys alongside server key
	authKeysFile := filepath.Join(tmp, "authorized_keys")
	if err := os.WriteFile(authKeysFile, []byte(validSSHKey+"\n"), 0600); err != nil {
		t.Fatalf("write authorized_keys: %v", err)
	}
	resolvedKeys, err := vault.ResolveSSHAuthorizedKeys(t.Context(), "", filepath.Join(tmp, "node-a.private.json"))
	if err != nil || len(resolvedKeys) != 1 {
		t.Fatalf("ResolveSSHAuthorizedKeys auto-discovery failed: err=%v, keys=%v", err, resolvedKeys)
	}

	// Verify auto-discovery of ssh_id_ed25519 relative to executable path
	fakeBinDir := filepath.Join(tmp, "bin")
	fakeMeshDir := filepath.Join(tmp, ".mesh")
	_ = os.MkdirAll(fakeBinDir, 0700)
	_ = os.MkdirAll(fakeMeshDir, 0700)
	fakeIdentity := filepath.Join(fakeMeshDir, "ssh_id_ed25519")
	_ = os.WriteFile(fakeIdentity, []byte("PRIVATE_KEY"), 0600)
	resolvedIdentity := vault.ResolveSSHIdentityFile("", filepath.Join(fakeBinDir, "mesh-bridge"))
	if resolvedIdentity != fakeIdentity {
		t.Fatalf("ResolveSSHIdentityFile got %q, want %q", resolvedIdentity, fakeIdentity)
	}
}

func TestStandaloneClientSSHProxyAndForwardParsing(t *testing.T) {
	vault := NewIdentityVault("")
	sc := NewStandaloneClient(vault, "/tmp/my.client.private.json", nil)

	proxyCmd, err := sc.buildSSHProxyCommand("/usr/local/bin/mesh-bridge", "tcTestAddr123", "22")
	if err != nil {
		t.Fatalf("buildSSHProxyCommand failed: %v", err)
	}
	if !strings.Contains(proxyCmd, "connect") || !strings.Contains(proxyCmd, "tcTestAddr123") {
		t.Fatalf("unexpected proxy command: %s", proxyCmd)
	}

	host1 := shortSSHDestHost("tcTestAddr123")
	host2 := shortSSHDestHost("tcTestAddr123")
	if host1 != host2 || !strings.HasPrefix(host1, "tailcat-") {
		t.Fatalf("unexpected shortSSHDestHost: %s vs %s", host1, host2)
	}

	if p, err := validateSSHPortSpec("2222"); err != nil || p != "2222" {
		t.Fatalf("validateSSHPortSpec(2222) = %q, %v", p, err)
	}
	if p, err := validateSSHPortSpec("10.0.0.5"); err != nil || p != "10.0.0.5:22" {
		t.Fatalf("validateSSHPortSpec(10.0.0.5) = %q, %v", p, err)
	}

	m1, err := parseForwardMapping("127.0.0.1", "2222:22")
	if err != nil || m1.listenAddr != "127.0.0.1:2222" || m1.port != 22 {
		t.Fatalf("parseForwardMapping(2222:22) = %+v, %v", m1, err)
	}
	m2, err := parseForwardMapping("", "8080")
	if err != nil || m2.listenAddr != "127.0.0.1:8080" || m2.port != 8080 {
		t.Fatalf("parseForwardMapping(8080) = %+v, %v", m2, err)
	}
}

func TestParseServedPorts(t *testing.T) {
	// Default empty spec: only SSH (22) and LocalPort (19100)
	ranges, allows := parseServedPorts(19100, "builtin", "")
	if len(ranges) != 2 || allows(18733) {
		t.Fatalf("expected only 22 and 19100 when empty, got ranges=%+v, allows(18733)=%v", ranges, allows(18733))
	}

	// Single and range ports in TAILCAT_SERVE_PORTS
	ranges, allows = parseServedPorts(19100, "builtin", "18733, 8080-8082")
	if len(ranges) != 4 {
		t.Fatalf("expected 4 port ranges, got %+v", ranges)
	}
	if !allows(18733) || !allows(8080) || !allows(8081) || !allows(8082) || allows(9090) {
		t.Fatalf("unexpected port matcher behavior for '18733, 8080-8082'")
	}

	// "all" mode
	ranges, allows = parseServedPorts(19100, "builtin", "all")
	if len(ranges) != 1 || ranges[0].First != 1 || ranges[0].Last != 65535 || !allows(18733) {
		t.Fatalf("unexpected 'all' port range: %+v", ranges)
	}
}

func TestMultiRegionCandidateSplitAndOrderedFailover(t *testing.T) {
	vault := NewIdentityVault("")
	pk := tailcat.NewPrivateKey()
	pk.Public.Region = []*tailcfg.DERPRegion{
		{
			RegionID: 901,
			Nodes: []*tailcfg.DERPNode{
				{
					Name:             "901a",
					RegionID:         901,
					HostName:         "8.133.228.233",
					IPv4:             "8.133.228.233",
					IPv6:             "none",
					STUNPort:         22648,
					DERPPort:         21683,
					InsecureForTests: true,
				},
			},
		},
		{
			RegionID: 900,
			Nodes: []*tailcfg.DERPNode{
				{
					Name:     "900a",
					RegionID: 900,
					HostName: "34.63.68.125",
					CertName: "sha256-raw:eef0494d5f0093d1a9caaca8d5bde6b1a45aac64225afb3d4c455673a1cc65b1",
					IPv4:     "34.63.68.125",
					IPv6:     "none",
					STUNPort: 3478,
					DERPPort: 443,
				},
			},
		},
	}

	multiAddr := pk.Public.Addr()
	candidates, err := vault.ParseCandidateAddrs(string(multiAddr))
	if err != nil {
		t.Fatalf("ParseCandidateAddrs failed: %v", err)
	}
	if len(candidates) != 2 {
		t.Fatalf("expected 2 single-region candidates, got %d", len(candidates))
	}

	ci0, err := tailcat.ParseAddr(candidates[0])
	if err != nil || len(ci0.Region) != 1 || ci0.Region[0].Nodes[0].HostName != "8.133.228.233" {
		t.Fatalf("unexpected candidate[0]: err=%v, region=%+v", err, ci0.Region)
	}
	ci1, err := tailcat.ParseAddr(candidates[1])
	if err != nil || len(ci1.Region) != 1 || ci1.Region[0].Nodes[0].HostName != "34.63.68.125" {
		t.Fatalf("unexpected candidate[1]: err=%v, region=%+v", err, ci1.Region)
	}

	// Verify deterministic Priority 1 -> Priority 2 failover order
	var dialedHosts []string
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	cl, conn, selectedAddr, err := vault.DialWithFailover(
		t.Context(),
		string(multiAddr),
		pk.Private,
		6*time.Second,
		nil,
		func(_ context.Context, candClient *tailcat.Client) (net.Conn, error) {
			parsed, err := tailcat.ParseAddr(candClient.Server)
			if err != nil {
				return nil, err
			}
			host := parsed.Region[0].Nodes[0].HostName
			dialedHosts = append(dialedHosts, host)
			if host == "8.133.228.233" {
				return nil, errors.New("simulated primary DERP 901 outage")
			}
			return c1, nil
		},
	)
	if err != nil {
		t.Fatalf("DialWithFailover failed: %v", err)
	}
	defer cl.Close()
	if conn != c1 {
		t.Fatalf("expected piped conn from fallback candidate")
	}
	if selectedAddr != candidates[1] {
		t.Fatalf("expected selectedAddr to be candidate[1], got %s", selectedAddr)
	}
	if len(dialedHosts) != 2 || dialedHosts[0] != "8.133.228.233" || dialedHosts[1] != "34.63.68.125" {
		t.Fatalf("unexpected failover dial sequence: %v", dialedHosts)
	}
}

func TestLoadEnvFile(t *testing.T) {
	tmp := t.TempDir()
	envPath := filepath.Join(tmp, "custom.env")
	content := strings.Join([]string{
		"# comment line",
		"",
		"TAILCAT_BRIDGE_PORT=29100 # inline comment",
		`export TAILCAT_SSH_MODE="local"`,
		`TAILCAT_SERVE_PORTS='8080,9000-9005'`,
		`TAILCAT_ALLOW_CLIENTS="nodekey:abc\"def"`,
		"TAILCAT_EMPTY=",
	}, "\n")
	if err := os.WriteFile(envPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	keys := []string{
		"TAILCAT_BRIDGE_PORT",
		"TAILCAT_SSH_MODE",
		"TAILCAT_SERVE_PORTS",
		"TAILCAT_ALLOW_CLIENTS",
		"TAILCAT_EMPTY",
	}
	for _, k := range keys {
		t.Setenv(k, "")
	}

	if err := loadEnvFile(envPath); err != nil {
		t.Fatalf("loadEnvFile failed: %v", err)
	}

	want := map[string]string{
		"TAILCAT_BRIDGE_PORT":   "29100",
		"TAILCAT_SSH_MODE":      "local",
		"TAILCAT_SERVE_PORTS":   "8080,9000-9005",
		"TAILCAT_ALLOW_CLIENTS": `nodekey:abc"def`,
		"TAILCAT_EMPTY":         "",
	}
	for k, w := range want {
		if got := os.Getenv(k); got != w {
			t.Errorf("env %s = %q, want %q", k, got, w)
		}
	}

	badPath := filepath.Join(tmp, "bad.env")
	if err := os.WriteFile(badPath, []byte("INVALID_LINE_WITHOUT_EQUALS\n"), 0o600); err != nil {
		t.Fatalf("write bad env file: %v", err)
	}
	if err := loadEnvFile(badPath); err == nil {
		t.Fatal("expected error for malformed env line, got nil")
	}

	if err := loadEnvFile(filepath.Join(tmp, "missing.env")); err == nil {
		t.Fatal("expected error for missing env file, got nil")
	}
}

func TestBuiltinSSHDirectTCPIPAndSFTP(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	pubLine := string(gossh.MarshalAuthorizedKey(signer.PublicKey()))

	handler := newBuiltinSSHHandler([]string{pubLine}, nil)
	sshLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen ssh: %v", err)
	}
	defer sshLn.Close()
	go func() {
		for {
			c, err := sshLn.Accept()
			if err != nil {
				return
			}
			go handler(c)
		}
	}()

	sshClient, err := gossh.Dial("tcp", sshLn.Addr().String(), &gossh.ClientConfig{
		User:            "testuser",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh dial builtin server: %v", err)
	}
	defer sshClient.Close()

	// 1. Non-interactive command execution (used by VS Code bootstrap script)
	sess, err := sshClient.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	out, err := sess.CombinedOutput("echo vscode-ready")
	_ = sess.Close()
	if err != nil {
		t.Fatalf("exec command failed: %v (output: %s)", err, string(out))
	}
	if strings.TrimSpace(string(out)) != "vscode-ready" {
		t.Fatalf("unexpected exec output: %q", string(out))
	}

	// 2. Local TCP port forwarding ("direct-tcpip") required by VS Code Remote - SSH
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo target: %v", err)
	}
	defer echoLn.Close()
	go func() {
		c, err := echoLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()

	tunConn, err := sshClient.Dial("tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatalf("direct-tcpip dial through builtin SSH failed: %v", err)
	}
	defer tunConn.Close()
	msg := "hello-vscode-tunnel"
	if _, err := io.WriteString(tunConn, msg); err != nil {
		t.Fatalf("write tunnel: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(tunConn, buf); err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("tunnel echo mismatch: got %q, want %q", string(buf), msg)
	}

	// 3. SFTP subsystem required by VS Code Remote file operations
	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		t.Fatalf("start sftp client over builtin SSH: %v", err)
	}
	defer sftpClient.Close()

	tmpFile := filepath.Join(t.TempDir(), "sftp_check.txt")
	f, err := sftpClient.Create(tmpFile)
	if err != nil {
		t.Fatalf("sftp create file: %v", err)
	}
	if _, err := f.Write([]byte("sftp-ok")); err != nil {
		t.Fatalf("sftp write: %v", err)
	}
	_ = f.Close()

	gotBytes, err := os.ReadFile(tmpFile)
	if err != nil || string(gotBytes) != "sftp-ok" {
		t.Fatalf("sftp file content mismatch: %v, %q", err, string(gotBytes))
	}
}

func TestRenderAndUpsertSSHConfig(t *testing.T) {
	tmp := t.TempDir()
	vault := NewIdentityVault("https://derp.example.com/derpmap.json")
	serverKeyPath := filepath.Join(tmp, "srv.private.json")
	tcAddr, err := vault.GenerateServerKey(t.Context(), serverKeyPath, false, true)
	if err != nil {
		t.Fatalf("GenerateServerKey: %v", err)
	}

	sc := NewStandaloneClient(vault, "client-dev", nil)
	sc.SSHIdentityFile = "/Users/dev/.ssh/id_ed25519"

	block1, err := sc.RenderSSHConfigBlock("my-dev", "root@"+string(tcAddr), "22", "/usr/local/bin/net_world")
	if err != nil {
		t.Fatalf("RenderSSHConfigBlock: %v", err)
	}
	for _, wantSub := range []string{
		"# BEGIN net_world:my-dev",
		"Host my-dev",
		"User root",
		"ProxyCommand '/usr/local/bin/net_world' '--client-key=client-dev' '--derpmap-url=https://derp.example.com/derpmap.json' 'connect' '" + string(tcAddr) + "' '22'",
		"IdentityFile /Users/dev/.ssh/id_ed25519",
		"# END net_world:my-dev",
	} {
		if !strings.Contains(block1, wantSub) {
			t.Fatalf("generated SSH config block missing %q:\n%s", wantSub, block1)
		}
	}

	cfgPath := filepath.Join(tmp, "ssh_config")
	if err := os.WriteFile(cfgPath, []byte("Host existing\n    HostName 10.0.0.1\n"), 0o600); err != nil {
		t.Fatalf("write initial ssh_config: %v", err)
	}

	if _, err := UpsertSSHConfigFile(cfgPath, "my-dev", block1); err != nil {
		t.Fatalf("UpsertSSHConfigFile insert: %v", err)
	}

	// Update with a new user and verify in-place replacement preserves existing host
	block2, err := sc.RenderSSHConfigBlock("my-dev", "ubuntu@"+string(tcAddr), "2222", "/usr/local/bin/net_world")
	if err != nil {
		t.Fatalf("RenderSSHConfigBlock update: %v", err)
	}
	if _, err := UpsertSSHConfigFile(cfgPath, "my-dev", block2); err != nil {
		t.Fatalf("UpsertSSHConfigFile update: %v", err)
	}

	finalRaw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read final ssh_config: %v", err)
	}
	finalStr := string(finalRaw)
	if !strings.Contains(finalStr, "Host existing") {
		t.Fatalf("existing Host entry lost:\n%s", finalStr)
	}
	if strings.Count(finalStr, "# BEGIN net_world:my-dev") != 1 {
		t.Fatalf("expected exactly 1 managed block, got:\n%s", finalStr)
	}
	if !strings.Contains(finalStr, "User ubuntu") || strings.Contains(finalStr, "User root") {
		t.Fatalf("expected updated block in ssh_config, got:\n%s", finalStr)
	}
}




