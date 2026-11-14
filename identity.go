// Package main provides a unified single-process Tailcat Mesh gateway (bridge)
// that manages both inbound Server connections and outbound Client stream pools.
package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// DiskDERPMapCache [Infrastructure Layer] implements tailcat.DERPMapCache on disk
// so DERP relay maps are cached across restarts without redundant network fetches.
type DiskDERPMapCache struct{}

func (DiskDERPMapCache) paths(url string) (dataPath, etagPath string, err error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", "", err
	}
	base := filepath.Join(dir, "tailcat", "derpmap-"+neturl.QueryEscape(url))
	return base + ".json", base + ".etag", nil
}

// Get retrieves the cached DERP map JSON, ETag, and modification timestamp.
func (c DiskDERPMapCache) Get(url string) (data []byte, etag string, storedAt time.Time, ok bool) {
	dataPath, etagPath, err := c.paths(url)
	if err != nil {
		return
	}
	fi, err := os.Stat(dataPath)
	if err != nil {
		return
	}
	data, err = os.ReadFile(dataPath)
	if err != nil {
		return
	}
	if v, err := os.ReadFile(etagPath); err == nil {
		etag = strings.TrimSpace(string(v))
	}
	return data, etag, fi.ModTime(), true
}

// Put stores the fetched DERP map JSON and ETag to disk.
func (c DiskDERPMapCache) Put(url string, data []byte, etag string) error {
	dataPath, etagPath, err := c.paths(url)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dataPath), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(dataPath, data, 0644); err != nil {
		return err
	}
	if etag == "" {
		_ = os.Remove(etagPath)
		return nil
	}
	return os.WriteFile(etagPath, []byte(etag), 0644)
}

// IdentityVault [Infrastructure Layer] owns the responsibility of loading,
// generating, and decoding Tailcat server/client keys (.private.json) and addresses (tc...).
type IdentityVault struct {
	DERPMapURL string
	Cache      tailcat.DERPMapCache
}

// NewIdentityVault creates an IdentityVault with default DERP map URL and disk cache.
func NewIdentityVault(derpMapURL string) *IdentityVault {
	return &IdentityVault{
		DERPMapURL: cmp.Or(derpMapURL, os.Getenv("TAILCAT_DERPMAP_URL"), tailcat.DefaultDERPMapURL),
		Cache:      DiskDERPMapCache{},
	}
}

// ResolveKeyPath resolves a key argument (either a file path or a named key in UserConfigDir).
func (v *IdentityVault) ResolveKeyPath(nameOrPath string) (string, error) {
	if strings.ContainsAny(nameOrPath, `/\`) || strings.HasSuffix(nameOrPath, ".private.json") {
		return nameOrPath, nil
	}
	confDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(confDir, "tailcat", "keys", nameOrPath+".private.json"), nil
}

// LoadServerKey reads and unmarshals a persisted server PrivateKey from disk.
func (v *IdentityVault) LoadServerKey(nameOrPath string) (*tailcat.PrivateKey, error) {
	if nameOrPath == "" || nameOrPath == "new" {
		pk := tailcat.NewPrivateKey()
		pk.Public.RegionID = -1
		return pk, nil
	}
	path, err := v.ResolveKeyPath(nameOrPath)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var conf tailcat.PrivateKey
	if err := json.Unmarshal(raw, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse server key %s: %w", path, err)
	}
	return &conf, nil
}

// LoadClientKey reads a persisted client NodePrivate key, or generates an ephemeral one if unset.
func (v *IdentityVault) LoadClientKey(nameOrPath string) (key.NodePrivate, error) {
	if nameOrPath == "" || nameOrPath == "new" {
		return key.NewNode(), nil
	}
	path, err := v.ResolveKeyPath(nameOrPath)
	if err != nil {
		return key.NodePrivate{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return key.NewNode(), nil
		}
		return key.NodePrivate{}, err
	}
	var conf tailcat.PrivateKey
	if err := json.Unmarshal(raw, &conf); err != nil {
		return key.NodePrivate{}, fmt.Errorf("failed to parse client key %s: %w", path, err)
	}
	return conf.Private, nil
}

// GenerateServerKey creates a new server key (.private.json), optionally probing for the nearest fixed DERP region.
func (v *IdentityVault) GenerateServerKey(ctx context.Context, keyArg string, fixedRegion bool, force bool) (tailcat.Addr, error) {
	path, err := v.ResolveKeyPath(keyArg)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(path); err == nil && !force {
		return "", fmt.Errorf("%s already exists; use --force to overwrite", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}

	priv := tailcat.NewPrivateKey()
	if fixedRegion {
		probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		dm, err := tailcat.FetchDERPMap(probeCtx, tailcat.DERPMapURL(v.DERPMapURL), tailcat.ExpandForServer, v.Cache)
		if err != nil {
			return "", fmt.Errorf("derpmap fetch: %w", err)
		}
		regID, err := tailcat.PickBestRegion(probeCtx, dm)
		if err != nil {
			return "", err
		}
		if regID == 0 {
			return "", errors.New("could not determine closest DERP region")
		}
		priv.Public.RegionID = regID
	} else {
		priv.Public.RegionID = -1
	}

	raw, err := json.MarshalIndent(priv, "", "\t")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		return "", err
	}
	return priv.Public.Addr(), nil
}

// GenerateClientKey creates a new client identity key (.client.private.json) and returns its public key string.
func (v *IdentityVault) GenerateClientKey(keyArg string, force bool) (string, error) {
	path, err := v.ResolveKeyPath(keyArg)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(path); err == nil && !force {
		return "", fmt.Errorf("%s already exists; use --force to overwrite", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}

	priv := tailcat.NewPrivateKey()
	raw, err := json.MarshalIndent(priv, "", "\t")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		return "", err
	}
	return priv.Private.Public().String(), nil
}

// ParseAddressJSON decodes a tailcat address (tc...) into formatted JSON.
func (v *IdentityVault) ParseAddressJSON(rawAddr string) ([]byte, error) {
	parsed, err := tailcat.ParseAddrRaw(tailcat.Addr(strings.TrimSpace(rawAddr)))
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(parsed, "", "    ")
}

// ResolvePeerAddr resolves the latest tailcat address for peerID from MESH_PEERS
// in .env (so hot-restarting mesh-bridge picks up updated DERP regions without
// restarting the parent Python process), falling back to fallbackAddr.
func (v *IdentityVault) ResolvePeerAddr(peerID string, fallbackAddr string) string {
	fb := strings.TrimSpace(fallbackAddr)
	pid := strings.TrimSpace(peerID)
	if fb == "" || pid == "" {
		return fb
	}
	rawPeers := readEnvValue("MESH_PEERS", ".env", filepath.Join("..", ".env"))
	if rawPeers == "" {
		return fb
	}
	for _, item := range strings.Split(rawPeers, ",") {
		item = strings.TrimSpace(item)
		name, spec, ok := strings.Cut(item, "=")
		if !ok || strings.TrimSpace(name) != pid {
			continue
		}
		spec = strings.TrimSpace(spec)
		if _, addrPart, hasAt := strings.Cut(spec, "@"); hasAt {
			addrPart = strings.TrimSpace(addrPart)
			if strings.HasPrefix(addrPart, "tc") {
				return addrPart
			}
		} else if strings.HasPrefix(spec, "tc") {
			return spec
		}
	}
	return fb
}

func readEnvValue(key string, candidateFiles ...string) string {
	for _, p := range candidateFiles {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			k, v, ok := strings.Cut(trimmed, "=")
			if !ok || strings.TrimSpace(k) != key {
				continue
			}
			val := strings.Trim(strings.TrimSpace(v), `"'`)
			if val != "" {
				return val
			}
		}
	}
	return strings.TrimSpace(os.Getenv(key))
}

// ParseCandidateAddrs decomposes a raw tailcat address (or comma-separated list of addresses)
// into an ordered slice of single-region tailcat.Addr candidates.
// Because tailcat.Client stores regions in a Go map and iterates it non-deterministically
// during handshake (locoBackend.derpRegionID), splitting multi-region addresses into
// single-region candidate addresses guarantees 100% deterministic priority ordering.
func (v *IdentityVault) ParseCandidateAddrs(rawAddr string) ([]tailcat.Addr, error) {
	var candidates []tailcat.Addr
	for _, token := range strings.Split(strings.TrimSpace(rawAddr), ",") {
		part := strings.TrimSpace(token)
		if part == "" {
			continue
		}
		addr := tailcat.Addr(part)
		ci, err := tailcat.ParseAddr(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid tailcat address %q: %w", part, err)
		}
		if len(ci.Region) <= 1 {
			candidates = append(candidates, addr)
			continue
		}
		for _, reg := range ci.Region {
			if reg == nil {
				continue
			}
			singleCI := tailcat.ConnInfo{
				ServerPublic:      ci.ServerPublic,
				ServerDiscoPublic: ci.ServerDiscoPublic,
				PresharedKey:      ci.PresharedKey,
				Region:            []*tailcfg.DERPRegion{reg},
			}
			candidates = append(candidates, singleCI.Addr())
		}
	}
	if len(candidates) == 0 {
		return nil, errors.New("empty tailcat address")
	}
	return candidates, nil
}

// NewCandidateClient constructs a tailcat.Client bound to a single-region candidate address.
func (v *IdentityVault) NewCandidateClient(candidateAddr tailcat.Addr, clientKey key.NodePrivate, logf logger.Logf) *tailcat.Client {
	if clientKey.IsZero() {
		clientKey = key.NewNode()
	}
	if logf == nil {
		logf = logger.Discard
	}
	return &tailcat.Client{
		Server:       candidateAddr,
		Key:          clientKey,
		Logf:         logf,
		DERPMapURL:   v.DERPMapURL,
		DERPMapCache: v.Cache,
	}
}

// DialWithFailover dials a peer across its ordered single-region DERP candidates,
// always attempting Candidate 0 (Primary DERP) first and failing over to subsequent
// candidates only if the higher-priority candidate fails or times out.
func (v *IdentityVault) DialWithFailover(
	ctx context.Context,
	rawAddr string,
	clientKey key.NodePrivate,
	totalTimeout time.Duration,
	logf logger.Logf,
	dialFn func(context.Context, *tailcat.Client) (net.Conn, error),
) (*tailcat.Client, net.Conn, tailcat.Addr, error) {
	candidates, err := v.ParseCandidateAddrs(rawAddr)
	if err != nil {
		return nil, nil, "", err
	}
	if totalTimeout <= 0 {
		totalTimeout = 10 * time.Second
	}
	overallStart := time.Now()
	var lastErr error

	for idx, candAddr := range candidates {
		remaining := totalTimeout - time.Since(overallStart)
		if remaining < 1500*time.Millisecond {
			remaining = 1500 * time.Millisecond
		}
		attemptBudget := remaining
		remainingCandidates := len(candidates) - idx
		if remainingCandidates > 1 {
			// Reserve budget for fallback candidates while giving the current priority
			// candidate enough time (at least 2.5s, up to 5.5s) to complete DERP handshake.
			perCandidate := remaining / time.Duration(remainingCandidates)
			attemptBudget = max(2500*time.Millisecond, min(perCandidate+1000*time.Millisecond, 5500*time.Millisecond))
			if attemptBudget > remaining {
				attemptBudget = remaining
			}
		}

		cl := v.NewCandidateClient(candAddr, clientKey, logf)
		dialCtx, cancel := context.WithTimeout(ctx, attemptBudget)
		conn, dialErr := dialFn(dialCtx, cl)
		cancel()
		if dialErr == nil {
			if idx > 0 && logf != nil {
				logf("[MeshBridge] failover connected via DERP candidate #%d", idx+1)
			}
			return cl, conn, candAddr, nil
		}

		_ = cl.Close()
		lastErr = dialErr
		if ctx.Err() != nil {
			break
		}
		if idx+1 < len(candidates) && logf != nil {
			logf("[MeshBridge] DERP candidate #%d/%d dial failed (%v); failing over to candidate #%d", idx+1, len(candidates), dialErr, idx+2)
		}
	}
	return nil, nil, "", lastErr
}

// LoadAllowedClientKeys parses a comma-separated list of client node public keys (e.g., "nodekey:...")
// or "none" to block all clients.
func (v *IdentityVault) LoadAllowedClientKeys(allowSpec string) ([]key.NodePublic, error) {
	spec := strings.TrimSpace(allowSpec)
	if spec == "" {
		return nil, nil
	}
	var allowed []key.NodePublic
	for _, ks := range strings.Split(spec, ",") {
		ks = strings.TrimSpace(ks)
		if ks == "" {
			continue
		}
		if ks == "none" {
			allowed = append(allowed, key.NodePublic{})
			continue
		}
		var k key.NodePublic
		if err := k.UnmarshalText([]byte(ks)); err != nil {
			return nil, fmt.Errorf("invalid client public key %q: %w", ks, err)
		}
		allowed = append(allowed, k)
	}
	return allowed, nil
}

const maxSSHAuthorizedKeysBytes = 1 << 20

var githubUsernameRegex = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)

// ResolveSSHAuthorizedKeys resolves authorized SSH public keys from an explicit spec
// (--ssh-authorized-keys / TAILCAT_SSH_AUTHORIZED_KEYS) or auto-discovers an authorized_keys
// file alongside the server key or in .mesh/authorized_keys.
func (v *IdentityVault) ResolveSSHAuthorizedKeys(ctx context.Context, explicitSpec string, serverKeyPath string) ([]string, error) {
	if spec := strings.TrimSpace(explicitSpec); spec != "" {
		return v.LoadSSHAuthorizedKeys(ctx, spec)
	}

	var candidates []string
	if kp := strings.TrimSpace(serverKeyPath); kp != "" && kp != "new" {
		if resolved, err := v.ResolveKeyPath(kp); err == nil {
			candidates = append(candidates, filepath.Join(filepath.Dir(resolved), "authorized_keys"))
		}
	}
	candidates = append(candidates, "authorized_keys", filepath.Join(".mesh", "authorized_keys"))

	for _, cand := range candidates {
		b, err := readAuthorizedKeysFile(cand)
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(b)) == "" {
			continue
		}
		return v.LoadSSHAuthorizedKeys(ctx, cand)
	}
	return nil, nil
}

// ResolveSSHIdentityFile determines the private key file (-i) for outbound SSH connections.
// Priority: explicit flag (-i/--identity) -> TAILCAT_SSH_IDENTITY_FILE -> auto-discovered .mesh/ssh_id_ed25519.
func (v *IdentityVault) ResolveSSHIdentityFile(explicitPath string, selfExePath string) string {
	if exp := strings.TrimSpace(explicitPath); exp != "" {
		return exp
	}
	if envPath := strings.TrimSpace(os.Getenv("TAILCAT_SSH_IDENTITY_FILE")); envPath != "" {
		return envPath
	}
	candidates := []string{
		filepath.Join(".mesh", "ssh_id_ed25519"),
		"ssh_id_ed25519",
	}
	if exe := strings.TrimSpace(selfExePath); exe != "" {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "..", ".mesh", "ssh_id_ed25519"),
			filepath.Join(exeDir, "ssh_id_ed25519"),
		)
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			if abs, err := filepath.Abs(c); err == nil {
				return abs
			}
			return c
		}
	}
	return ""
}

// LoadSSHAuthorizedKeys resolves a comma-separated list of SSH authorized_keys sources:
// file paths, literal OpenSSH public key lines, or "user@github".
func (v *IdentityVault) LoadSSHAuthorizedKeys(ctx context.Context, sourceList string) ([]string, error) {
	spec := strings.TrimSpace(sourceList)
	if spec == "" {
		return nil, nil
	}
	var texts []string
	for idx, src := range strings.Split(spec, ",") {
		src = strings.TrimSpace(src)
		if src == "" {
			continue
		}
		var (
			raw []byte
			err error
		)
		if ghUser, ok := strings.CutSuffix(src, "@github"); ok {
			if !githubUsernameRegex.MatchString(ghUser) {
				return nil, fmt.Errorf("source %d: invalid GitHub username %q", idx+1, ghUser)
			}
			raw, err = fetchGitHubPublicKeys(ctx, ghUser)
			if err != nil {
				return nil, fmt.Errorf("source %d (%s): %w", idx+1, src, err)
			}
		} else if fileBytes, fileErr := readAuthorizedKeysFile(src); fileErr == nil {
			raw = fileBytes
		} else if valErr := tailcat.ValidateSSHAuthorizedKeys([]string{src}); valErr == nil {
			raw = []byte(src)
		} else {
			return nil, fmt.Errorf("source %d (%s): %w", idx+1, src, fileErr)
		}

		if err := tailcat.ValidateSSHAuthorizedKeys([]string{string(raw)}); err != nil {
			return nil, fmt.Errorf("source %d (%s): %w", idx+1, src, err)
		}
		texts = append(texts, string(raw))
	}
	if len(texts) > 0 {
		if err := tailcat.ValidateSSHAuthorizedKeys(texts); err != nil {
			return nil, err
		}
	}
	return texts, nil
}

func readAuthorizedKeysFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxSSHAuthorizedKeysBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxSSHAuthorizedKeysBytes {
		return nil, fmt.Errorf("authorized_keys file exceeds %d bytes", maxSSHAuthorizedKeysBytes)
	}
	return b, nil
}

func fetchGitHubPublicKeys(ctx context.Context, ghUser string) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	u := "https://github.com/" + neturl.PathEscape(ghUser) + ".keys"
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "mesh-bridge")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github keys HTTP %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxSSHAuthorizedKeysBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxSSHAuthorizedKeysBytes {
		return nil, fmt.Errorf("github key list exceeds %d bytes", maxSSHAuthorizedKeysBytes)
	}
	return b, nil
}

// TrimDERPRegion strips unnecessary metadata fields from a DERPRegion before constructing a Server.
func TrimDERPRegion(r *tailcfg.DERPRegion) {
	if r == nil {
		return
	}
	if r.RegionID == 0 {
		r.RegionID = 1
	}
	r.Latitude = 0
	r.Longitude = 0
	r.RegionCode = ""
	if len(r.Nodes) > 1 {
		r.Nodes = r.Nodes[:1]
	}
	for _, n := range r.Nodes {
		n.CanPort80 = false
		n.RegionID = r.RegionID
	}
}

