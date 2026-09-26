//go:build !windows

package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testSystem = "sys-0123456789"

type fixture struct {
	t        *testing.T
	priv     ed25519.PrivateKey
	keysFile string
	nonce    string
	now      time.Time
	mono     *atomic.Int64
	window   *Window
	ctl      *Controller
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	_, privPath := mustKeygen(t, filepath.Join(dir, "operator"))
	priv, err := LoadPrivateKey(privPath)
	if err != nil {
		t.Fatal(err)
	}
	keysDir := filepath.Join(dir, "etc")
	if err := os.Mkdir(keysDir, 0755); err != nil {
		t.Fatal(err)
	}
	keysFile := filepath.Join(keysDir, "control-stop-keys.pub")
	writeKeys(t, keysFile, 0644, priv.Public().(ed25519.PublicKey))
	f := &fixture{t: t, priv: priv, keysFile: keysFile, nonce: filepath.Join(dir, "data", NonceFileName), now: time.Unix(1_800_000_000, 0), mono: &atomic.Int64{}}
	f.window = newWindow(func() time.Duration { return time.Duration(f.mono.Load()) })
	f.ctl = f.controller()
	return f
}

func (f *fixture) controller() *Controller {
	f.t.Helper()
	ctl, err := New(Config{
		KeysFile:  f.keysFile,
		KeysOwner: uint32(os.Getuid()),
		NonceFile: f.nonce,
		SystemID:  func() (string, error) { return testSystem, nil },
		Window:    f.window,
		Now:       func() time.Time { return f.now },
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return ctl
}

func mustKeygen(t *testing.T, dir string) (pubPath, privPath string) {
	t.Helper()
	privPath, pubPath, _, err := GenerateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	return pubPath, privPath
}

func writeKeys(t *testing.T, path string, mode os.FileMode, keys ...ed25519.PublicKey) {
	t.Helper()
	var b strings.Builder
	b.WriteString("# trusted darkd stop keys\n\n")
	for _, k := range keys {
		b.WriteString(base64.StdEncoding.EncodeToString(k) + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) claims(action string) Claims {
	f.t.Helper()
	c, err := NewClaims(action, testSystem, f.now, 10*time.Minute)
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

func (f *fixture) token(c Claims) string {
	f.t.Helper()
	tok, err := SignToken(f.priv, c)
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

// signRaw signs arbitrary payload bytes, for encodings SignToken never emits.
func signRaw(priv ed25519.PrivateKey, payload []byte) string {
	sig := ed25519.Sign(priv, signedMessage(payload))
	return tokenPrefix + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func noAudit(Grant) error { return nil }

func (f *fixture) mustReject(name string, tok string, want error) {
	f.t.Helper()
	_, err := f.ctl.Authorize([]byte(tok), noAudit)
	if err == nil {
		f.t.Fatalf("%s: token accepted", name)
	}
	if want != nil && !errors.Is(err, want) {
		f.t.Fatalf("%s: got %v, want %v", name, err, want)
	}
	if f.window.Open() {
		f.t.Fatalf("%s: window opened after rejection", name)
	}
}

func TestValidTokenOpensWindowAndAudits(t *testing.T) {
	f := newFixture(t)
	var audited Grant
	grant, err := f.ctl.Authorize([]byte(f.token(f.claims(ActionUpgrade))+"\n"), func(g Grant) error {
		if f.window.Open() {
			t.Fatal("window opened before the audit record was written")
		}
		audited = g
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !f.window.Open() {
		t.Fatal("window not open after a valid token")
	}
	if grant.Action != ActionUpgrade || grant.SystemID != testSystem || grant.Window != MaintenanceWindow {
		t.Fatalf("grant: %+v", grant)
	}
	if grant != audited || !strings.HasPrefix(grant.KeyFingerprint, "SHA256:") || len(grant.NonceHash) != 64 {
		t.Fatalf("audit record: %+v", audited)
	}
}

func TestWindowExpiresAfter120Seconds(t *testing.T) {
	f := newFixture(t)
	if f.window.Open() {
		t.Fatal("window open before any token")
	}
	if _, err := f.ctl.Authorize([]byte(f.token(f.claims(ActionStop))), noAudit); err != nil {
		t.Fatal(err)
	}
	f.mono.Store(int64(119 * time.Second))
	if !f.window.Open() {
		t.Fatal("window closed early")
	}
	f.mono.Store(int64(120 * time.Second))
	if f.window.Open() {
		t.Fatal("window still open at 120s")
	}
	var nilWindow *Window
	if nilWindow.Open() {
		t.Fatal("nil window reported open")
	}
}

func TestTamperedPayloadAndSignatureRejected(t *testing.T) {
	f := newFixture(t)
	tok := f.token(f.claims(ActionStop))
	parts := strings.Split(tok, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	for i := range payload {
		changed := append([]byte(nil), payload...)
		changed[i] ^= 0x01
		f.mustReject("payload byte", parts[0]+"."+base64.RawURLEncoding.EncodeToString(changed)+"."+parts[2], nil)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	for _, i := range []int{0, 31, 63} {
		changed := append([]byte(nil), sig...)
		changed[i] ^= 0x80
		f.mustReject("signature byte", parts[0]+"."+parts[1]+"."+base64.RawURLEncoding.EncodeToString(changed), ErrBadSignature)
	}
	// The untampered token still works: the rejections consumed nothing.
	if _, err := f.ctl.Authorize([]byte(tok), noAudit); err != nil {
		t.Fatal(err)
	}
}

func TestWrongKeyRejected(t *testing.T) {
	f := newFixture(t)
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := SignToken(other, f.claims(ActionStop))
	if err != nil {
		t.Fatal(err)
	}
	f.mustReject("wrong key", tok, ErrBadSignature)
}

func TestTimeBoundsRejected(t *testing.T) {
	f := newFixture(t)
	expired := f.claims(ActionStop)
	f.now = time.Unix(expired.NotAfter+1, 0)
	f.mustReject("expired", f.token(expired), ErrExpired)

	f.now = time.Unix(1_800_000_000, 0)
	long := f.claims(ActionStop)
	long.NotAfter = long.IssuedAt + int64(MaxTokenLifetime/time.Second) + 1
	f.mustReject("lifetime over 15m", f.token(long), ErrLifetime)

	inverted := f.claims(ActionStop)
	inverted.NotAfter = inverted.IssuedAt
	f.mustReject("zero lifetime", f.token(inverted), ErrLifetime)

	future := f.claims(ActionStop)
	future.IssuedAt = f.now.Add(MaxClockSkew + time.Second).Unix()
	future.NotAfter = future.IssuedAt + 60
	f.mustReject("issued in the future", f.token(future), ErrFutureIssuedAt)

	skewed := f.claims(ActionStop)
	skewed.IssuedAt = f.now.Add(MaxClockSkew - time.Second).Unix()
	skewed.NotAfter = skewed.IssuedAt + 60
	if _, err := f.ctl.Authorize([]byte(f.token(skewed)), noAudit); err != nil {
		t.Fatalf("issued_at within skew rejected: %v", err)
	}
}

func TestClaimsRejected(t *testing.T) {
	f := newFixture(t)
	wrongSystem := f.claims(ActionStop)
	wrongSystem.SystemID = "sys-other"
	f.mustReject("wrong system", f.token(wrongSystem), ErrWrongSystem)

	version := f.claims(ActionStop)
	version.Version = 2
	f.mustReject("version", f.token(version), ErrBadVersion)

	action := f.claims(ActionStop)
	action.Action = "restart"
	f.mustReject("action", f.token(action), ErrBadAction)

	short := f.claims(ActionStop)
	short.Nonce = base64.RawURLEncoding.EncodeToString(make([]byte, MinNonceSize-1))
	f.mustReject("short nonce", f.token(short), ErrBadNonce)

	padded := f.claims(ActionStop)
	padded.Nonce = base64.URLEncoding.EncodeToString(make([]byte, 32))
	f.mustReject("padded nonce", f.token(padded), ErrBadNonce)

	if _, err := NewClaims("stop", testSystem, f.now, 16*time.Minute); !errors.Is(err, ErrLifetime) {
		t.Fatalf("NewClaims accepted a 16m ttl: %v", err)
	}
	if _, err := NewClaims("kill", testSystem, f.now, time.Minute); !errors.Is(err, ErrBadAction) {
		t.Fatalf("NewClaims accepted action kill: %v", err)
	}
}

func TestMalformedEncodingRejected(t *testing.T) {
	f := newFixture(t)
	valid := f.claims(ActionStop)
	canonical, _ := json.Marshal(valid)
	good := f.token(valid)
	parts := strings.Split(good, ".")
	reordered := `{"action":"stop","version":1,"system_id":"` + testSystem + `","nonce":"` + valid.Nonce + `","issued_at":` + jsonInt(valid.IssuedAt) + `,"not_after":` + jsonInt(valid.NotAfter) + `}`
	cases := map[string]string{
		"empty":           "",
		"prefix only":     tokenPrefix,
		"two parts":       tokenPrefix + "." + parts[1],
		"four parts":      good + ".x",
		"wrong prefix":    "darkdctl2." + parts[1] + "." + parts[2],
		"padded payload":  tokenPrefix + "." + base64.URLEncoding.EncodeToString(canonical) + "." + parts[2],
		"std alphabet":    tokenPrefix + "." + strings.NewReplacer("-", "+", "_", "/").Replace(parts[1]) + "+/." + parts[2],
		"short signature": tokenPrefix + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 63)),
		"not json":        signRaw(f.priv, []byte("action=stop\nsystem_id="+testSystem)),
		"whitespace json": signRaw(f.priv, append([]byte(" "), canonical...)),
		"reordered json":  signRaw(f.priv, []byte(reordered)),
		"unknown field":   signRaw(f.priv, []byte(strings.TrimSuffix(string(canonical), "}")+`,"extra":1}`)),
		"duplicate field": signRaw(f.priv, []byte(strings.Replace(string(canonical), `"action":"stop"`, `"action":"upgrade","action":"stop"`, 1))),
		"trailing data":   signRaw(f.priv, append(append([]byte(nil), canonical...), []byte("{}")...)),
		"case folded key": signRaw(f.priv, []byte(strings.Replace(string(canonical), `"action"`, `"ACTION"`, 1))),
	}
	for name, tok := range cases {
		f.mustReject(name, tok, nil)
	}
}

func jsonInt(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestOversizedTokenRejected(t *testing.T) {
	f := newFixture(t)
	good := f.token(f.claims(ActionStop))
	f.mustReject("oversized", good+strings.Repeat(" ", MaxTokenSize), ErrTokenTooLarge)
	f.mustReject("4097 bytes", strings.Repeat("A", MaxTokenSize+1), ErrTokenTooLarge)
	big := f.claims(ActionStop)
	big.SystemID = strings.Repeat("x", MaxTokenSize)
	if _, err := SignToken(f.priv, big); !errors.Is(err, ErrTokenTooLarge) {
		t.Fatalf("SignToken produced an oversized token: %v", err)
	}
}

func TestReplayRejectedIncludingAfterRestart(t *testing.T) {
	f := newFixture(t)
	tok := f.token(f.claims(ActionStop))
	if _, err := f.ctl.Authorize([]byte(tok), noAudit); err != nil {
		t.Fatal(err)
	}
	f.mono.Store(int64(MaintenanceWindow))
	f.mustReject("replay", tok, ErrReplay)

	// A new controller, fresh window, same storage: a daemon restart.
	f.window = newWindow(func() time.Duration { return time.Duration(f.mono.Load()) })
	f.ctl = f.controller()
	f.mustReject("replay after restart", tok, ErrReplay)

	info, err := os.Stat(f.nonce)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("nonce store mode %04o", info.Mode().Perm())
	}
	data, err := os.ReadFile(f.nonce)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), strings.Split(tok, ".")[1]) {
		t.Fatal("nonce store holds token material")
	}
}

func TestNonceStorePrunesAndFailsClosed(t *testing.T) {
	dir := t.TempDir()
	store := NewNonceStore(filepath.Join(dir, NonceFileName))
	now := time.Unix(1_800_000_000, 0)
	h := strings.Repeat("a", 64)
	if err := store.Consume(h, now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if err := store.Consume(h, now.Add(time.Minute), now); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay: %v", err)
	}
	// Past not_after the entry is pruned; the token would be expired anyway.
	if err := store.Consume(h, now.Add(10*time.Minute), now.Add(2*time.Minute)); err != nil {
		t.Fatalf("pruned entry still blocks: %v", err)
	}
	if err := store.Consume("not-a-hash", now, now); err == nil {
		t.Fatal("invalid hash accepted")
	}
	full := map[string]int64{}
	for i := 0; i < maxNonceEntries; i++ {
		full[strings.Repeat("0", 56)+hex8(i)] = now.Add(time.Hour).Unix()
	}
	if err := store.save(full); err != nil {
		t.Fatal(err)
	}
	if err := store.Consume(strings.Repeat("b", 64), now.Add(time.Minute), now); !errors.Is(err, ErrNonceStoreFull) {
		t.Fatalf("full store: %v", err)
	}
	if err := os.WriteFile(store.path, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.Consume(strings.Repeat("c", 64), now.Add(time.Minute), now); err == nil {
		t.Fatal("corrupt store accepted a nonce")
	}
	if err := os.WriteFile(store.path, []byte(`{"version":1,"nonces":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(store.path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := store.Consume(strings.Repeat("c", 64), now.Add(time.Minute), now); err == nil {
		t.Fatal("world-readable store accepted a nonce")
	}
}

func hex8(i int) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 8)
	for j := 7; j >= 0; j-- {
		out[j] = digits[i&0xf]
		i >>= 4
	}
	return string(out)
}

func TestNoKeysConfiguredRejected(t *testing.T) {
	f := newFixture(t)
	tok := f.token(f.claims(ActionStop))
	f.keysFile = ""
	f.ctl = f.controller()
	f.mustReject("no key file configured", tok, ErrNoKeys)

	f.keysFile = filepath.Join(filepath.Dir(f.nonce), "..", "etc", "missing.pub")
	f.ctl = f.controller()
	f.mustReject("key file missing", tok, ErrNoKeys)

	empty := filepath.Join(t.TempDir(), "empty.pub")
	writeKeys(t, empty, 0644)
	f.keysFile = empty
	f.ctl = f.controller()
	f.mustReject("key file with only comments", tok, ErrNoKeys)

	if _, err := verifyToken([]byte(tok), nil, testSystem, f.now); !errors.Is(err, ErrNoKeys) {
		t.Fatalf("verify with no keys: %v", err)
	}
}

func TestUntrustedKeyFileRejected(t *testing.T) {
	f := newFixture(t)
	tok := f.token(f.claims(ActionStop))
	pub := f.priv.Public().(ed25519.PublicKey)

	for _, mode := range []os.FileMode{0666, 0646, 0664, 0620} {
		writeKeys(t, f.keysFile, mode, pub)
		f.mustReject("key file mode", tok, nil)
	}
	writeKeys(t, f.keysFile, 0644, pub)

	dir := filepath.Dir(f.keysFile)
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	f.mustReject("world-writable key directory", tok, nil)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}

	// Ownership: the file is owned by the test uid, so requiring any other
	// owner (root, when the test is not root) must reject it.
	ctl, err := New(Config{KeysFile: f.keysFile, KeysOwner: uint32(os.Getuid()) + 1, NonceFile: f.nonce,
		SystemID: func() (string, error) { return testSystem, nil }, Window: f.window, Now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctl.Authorize([]byte(tok), noAudit); err == nil || !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("key file owned by the wrong uid accepted: %v", err)
	}
	if os.Getuid() != 0 {
		if _, err := LoadPublicKeys(f.keysFile, 0); err == nil {
			t.Fatal("non-root-owned key file accepted as root-owned")
		}
	}

	link := filepath.Join(dir, "link.pub")
	if err := os.Symlink(f.keysFile, link); err != nil {
		t.Fatal(err)
	}
	f.keysFile = link
	f.ctl = f.controller()
	f.mustReject("symlinked key file", tok, nil)

	garbage := filepath.Join(dir, "garbage.pub")
	if err := os.WriteFile(garbage, []byte("not-a-key\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f.keysFile = garbage
	f.ctl = f.controller()
	f.mustReject("garbage key line", tok, nil)

	if f.window.Open() {
		t.Fatal("window opened")
	}
}

func TestMultipleKeysAnyMayVerify(t *testing.T) {
	f := newFixture(t)
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeKeys(t, f.keysFile, 0644, otherPub, f.priv.Public().(ed25519.PublicKey))
	grant, err := f.ctl.Authorize([]byte(f.token(f.claims(ActionStop))), noAudit)
	if err != nil {
		t.Fatal(err)
	}
	if grant.KeyFingerprint != Fingerprint(f.priv.Public().(ed25519.PublicKey)) {
		t.Fatal("grant names the wrong key")
	}
}

func TestAuditFailureKeepsWindowClosedAndBurnsNonce(t *testing.T) {
	f := newFixture(t)
	tok := f.token(f.claims(ActionStop))
	if _, err := f.ctl.Authorize([]byte(tok), func(Grant) error { return errors.New("journal down") }); err == nil {
		t.Fatal("authorized without an audit record")
	}
	if f.window.Open() {
		t.Fatal("window opened without an audit record")
	}
	f.mustReject("retry after audit failure", tok, ErrReplay)
	if _, err := f.ctl.Authorize([]byte(f.token(f.claims(ActionStop))), nil); err == nil {
		t.Fatal("authorized with no audit sink")
	}
}

func TestKeygenAndPrivateKeyHandling(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath, pub, err := GenerateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(privPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private key mode: %v %v", info, err)
	}
	if _, _, _, err := GenerateKeyPair(dir); err == nil {
		t.Fatal("keygen overwrote an existing key")
	}
	priv, err := LoadPrivateKey(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.Public().(ed25519.PublicKey).Equal(pub) {
		t.Fatal("private key does not match public key")
	}
	keys, err := LoadPublicKeys(pubPath, uint32(os.Getuid()))
	if err != nil || len(keys) != 1 {
		t.Fatalf("public key file: %d keys, %v", len(keys), err)
	}
	if err := os.Chmod(privPath, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(privPath); err == nil {
		t.Fatal("group-readable private key accepted")
	}
}
