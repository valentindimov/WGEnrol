package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"thebasstoon.com/wgenrol/internal/storage/sqlite"
)

// WireGuard device control is gated on the same test.sh-provided flag the
// wireguard package's device tests use. Interface names are package-local
// constants so concurrent test binaries in the shared network namespace
// never collide.
const deviceControlEnv = "WGENROL_TEST_WIREGUARD_DEVICE_CONTROL"
const serveIfname = "wgenrol-serve"

func runIP(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

// deviceServeSetup gates the serve-tail tests and creates the WireGuard
// interface the config references (its removal is bound to the test's
// cleanup). With the interface present, run()'s startup apply succeeds and
// the serve tail is actually reached.
func deviceServeSetup(t *testing.T) {
	t.Helper()
	if os.Getenv(deviceControlEnv) == "" {
		t.Skipf("%s is not set: skipping serve-tail tests (enabled automatically by test.sh inside its network namespace)", deviceControlEnv)
	}
	runIP(t, "link", "add", serveIfname, "type", "wireguard")
	t.Cleanup(func() { runIP(t, "link", "del", serveIfname) })
}

// keyB64 returns a valid base64-encoded 32-byte key.
func keyB64(fill byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

// writeRunConfig writes a minimal valid config pointing at dbPath. listenOn
// determines where the server would bind (tests use an unusable address so a
// serve attempt terminates instead of blocking).
func writeRunConfig(t *testing.T, dbPath, listenOn, ifname string) string {
	t.Helper()
	var tlsPair [2]string
	return writeRunConfigTLS(t, dbPath, listenOn, ifname, tlsPair)
}

// writeRunConfigTLS writes a config like writeRunConfig, optionally with TLS
// enabled (cert/key must be file paths when non-nil).
func writeRunConfigTLS(t *testing.T, dbPath, listenOn, ifname string, certPair [2]string) string {
	t.Helper()
	tlsBlock := "  tls:\n    enabled: false\n"
	if certPair != ([2]string{}) {
		tlsBlock = "  tls:\n    enabled: true\n    certFile: \"" + certPair[0] + "\"\n    keyFile: \"" + certPair[1] + "\"\n"
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(`server:
  listenOn: "`+listenOn+`"
`+tlsBlock+`smtp:
  enabled: false
storage:
  file: "`+dbPath+`"
wireguard:
  ifname: "`+ifname+`"
advertise:
  endpoint: "127.0.0.1:51820"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// writeImportConf writes a wg-quick conf fixture with the given peer block.
func writeImportConf(t *testing.T, peerBlock string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "wg.conf")
	conf := "[Interface]\nPrivateKey = " + keyB64(9) + "\nAddress = 10.64.0.1/24\nListenPort = 51820\n\n" + peerBlock
	if err := os.WriteFile(p, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

var alicePeer = "# Alice\n[Peer]\nPublicKey = " + keyB64(1) + "\nAllowedIPs = 10.64.0.2/32\n"
var bobPeer = "# Bob\n[Peer]\nPublicKey = " + keyB64(2) + "\nAllowedIPs = 10.64.1.2/32\n"

func TestRunImport(t *testing.T) {
	db := filepath.Join(t.TempDir(), "peers.db")
	store, err := sqlite.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	conf := writeImportConf(t, alicePeer+bobPeer+"# Charlie\n[Peer]\nPublicKey = "+keyB64(3)+"\nAllowedIPs = 10.64.2.2/32\n")

	imported, skipped, err := runImport(store, conf)
	if err != nil || imported != 3 || skipped != 0 {
		t.Fatalf("import: expected (3, 0, nil), got (%d, %d, %v)", imported, skipped, err)
	}
	peers, err := store.ListPeers()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 3 {
		t.Fatalf("expected 3 imported peers, got %d", len(peers))
	}
	for i, want := range []string{"Alice", "Bob", "Charlie"} {
		if peers[i].Comment != want {
			t.Errorf("peer %d: expected comment %q, got %q", i, want, peers[i].Comment)
		}
	}

	// Import is add-only and idempotent: a re-run skips everything, a changed
	// file mixes skips with new imports, and DB-side deletions are never
	// replicated from the conf file.
	imported, skipped, err = runImport(store, conf)
	if err != nil || imported != 0 || skipped != 3 {
		t.Fatalf("re-import: expected (0, 3, nil), got (%d, %d, %v)", imported, skipped, err)
	}
	conf2 := writeImportConf(t, alicePeer+"# Dana\n[Peer]\nPublicKey = "+keyB64(4)+"\nAllowedIPs = 10.64.3.2/32\n")
	imported, skipped, err = runImport(store, conf2)
	if err != nil || imported != 1 || skipped != 1 {
		t.Fatalf("mixed import: expected (1, 1, nil), got (%d, %d, %v)", imported, skipped, err)
	}
}

// run() with an import path must import and then continue into the serve
// path. In the test environment that path terminates on its own (the
// nonexistent WireGuard interface fails the device apply, or the bind fails),
// so the test asserts on the import side effects without blocking.
func TestRunImportThenServe(t *testing.T) {
	db := filepath.Join(t.TempDir(), "peers.db")
	cfg := writeRunConfig(t, db, "127.0.0.1:1", "wgenrol-test")
	conf := writeImportConf(t, alicePeer+bobPeer)

	if err := run(cfg, conf); err == nil {
		t.Fatal("expected the serve path to terminate with an error in the test environment")
	}

	store, err := sqlite.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	peers, err := store.ListPeers()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 {
		t.Fatalf("expected the imported peers to persist after the serve attempt, got %d", len(peers))
	}
	for _, peer := range peers {
		if peer.Comment != "Alice" && peer.Comment != "Bob" {
			t.Errorf("unexpected peer comment %q", peer.Comment)
		}
	}
}

func TestRunImportErrors(t *testing.T) {
	db := filepath.Join(t.TempDir(), "peers.db")
	store, err := sqlite.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	cases := []struct {
		name       string
		peerBlock  string
		wantSubstr string
	}{
		{"no interface section", alicePeer, "No Interface section"},
		{"invalid key", "# Bad\n[Peer]\nPublicKey = NOT-A-KEY\nAllowedIPs = 10.64.0.2/32\n", "Invalid peer"},
		{"missing allowed IPs", "# No IPs\n[Peer]\nPublicKey = " + keyB64(5) + "\n", "AllowedIPs cannot be empty"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conf := writeImportConfNoInterface(t, c.peerBlock, c.name)
			if _, _, err := runImport(store, conf); err == nil || !strings.Contains(err.Error(), c.wantSubstr) {
				t.Fatalf("expected error containing %q, got %v", c.wantSubstr, err)
			}
		})
	}
}

// writeImportConfNoInterface writes a conf fixture, optionally omitting the
// [Interface] section entirely.
func writeImportConfNoInterface(t *testing.T, peerBlock, name string) string {
	t.Helper()
	if name != "no interface section" {
		return writeImportConf(t, peerBlock)
	}
	p := filepath.Join(t.TempDir(), "wg.conf")
	if err := os.WriteFile(p, []byte(peerBlock), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunConfigErrors(t *testing.T) {
	if err := run(filepath.Join(t.TempDir(), "nope", "config.yaml"), ""); err == nil {
		t.Fatal("expected an error for a missing config file")
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	missing := `server:
  listenOn: "127.0.0.1:8080"
smtp:
  enabled: false
wireguard:
  ifname: "wgenrol-test"
advertise:
  endpoint: "127.0.0.1:51820"
`
	if err := os.WriteFile(p, []byte(missing), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(p, ""); err == nil || !strings.Contains(err.Error(), "storage.file") {
		t.Fatalf("expected missing-storage.file error, got %v", err)
	}
	broken := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(broken, []byte("server: {listenOn: \"[unclosed\""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(broken, ""); err == nil {
		t.Fatal("expected a YAML parsing error")
	}
}

// An unreachable PostgreSQL server must fail at startup with a connection
// error (the schema creation forces the connection).
func TestRunPostgresUnreachable(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	pg := `server:
  listenOn: "127.0.0.1:8080"
smtp:
  enabled: false
storage:
  backend: postgres
  dsn: "postgres://wgenrol-test@127.0.0.1:1/wgenrol"
wireguard:
  ifname: "wgenrol-test"
advertise:
  endpoint: "127.0.0.1:51820"
`
	if err := os.WriteFile(p, []byte(pg), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(p, ""); err == nil {
		t.Fatal("expected a connection error for an unreachable PostgreSQL server")
	}
}

// genServeCertPair generates a throwaway self-signed ECDSA cert/key pair as
// PEM files and returns their paths. Mirrors the server package's
// genSelfSigned helper (test helpers stay package-local per AGENTS.md).
func genServeCertPair(t *testing.T) [2]string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "wgenrol-serve"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return [2]string{certPath, keyPath}
}

// The serve tail of run() is reached when the startup device apply succeeds.
// Pre-binding the listener's port makes the subsequent bind fail with
// "address already in use", so run() terminates deterministically (the actual
// blocking serve loop is covered through serve() tests in internal/server).
func TestRunServeTail(t *testing.T) {
	deviceServeSetup(t)
	db := filepath.Join(t.TempDir(), "peers.db")

	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer reserved.Close()
	cfg := writeRunConfig(t, db, reserved.Addr().String(), serveIfname)

	result := make(chan error, 1)
	go func() { result <- run(cfg, "") }()
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("expected an address-already-in-use error from the serve tail, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run() did not terminate after reaching the serve tail within 10 s")
	}
}

// Same serve-tail coverage with TLS enabled, so both listening-mode log
// branches execute.
func TestRunServeTailTLS(t *testing.T) {
	deviceServeSetup(t)
	db := filepath.Join(t.TempDir(), "peers.db")

	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer reserved.Close()
	cfg := writeRunConfigTLS(t, db, reserved.Addr().String(), serveIfname, genServeCertPair(t))

	result := make(chan error, 1)
	go func() { result <- run(cfg, "") }()
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("expected an address-already-in-use error from the serve tail, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run() did not terminate after reaching the serve tail within 10 s")
	}
}
