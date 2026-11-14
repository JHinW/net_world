package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/tailcat"
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


