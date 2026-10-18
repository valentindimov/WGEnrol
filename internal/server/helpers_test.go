package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"thebasstoon.com/wgenrol/internal/config"
	"thebasstoon.com/wgenrol/internal/storage/sqlite"
)

// bcrypt hash of the password "password" (matches testdata/test_config.yaml).
const testPasswordHash = "$2a$08$noE9l0k/bSRj0cyRaVsDsue4L2WEmHP9pHxfGOJ026xEttfFn3TFq"

// validKey returns a syntactically valid (32-byte) WireGuard key in std base64.
func validKey() string { return base64.StdEncoding.EncodeToString(make([]byte, 32)) }

// prefixes parses CIDR strings into a []netip.Prefix.
func prefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// newLoginCtx builds a ServerContext with a single admin user (admin/"password")
// and a temporary SQLite session store (the handlers under test only touch
// sessions, not peers).
func newLoginCtx(t *testing.T) *ServerContext {
	t.Helper()
	store, err := sqlite.Open(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	ctx := &ServerContext{
		Config:   &config.WgEnrolConfig{},
		Sessions: store,
	}
	ctx.Config.Admin.Users = map[string]string{"admin": testPasswordHash}
	return ctx
}

// deviceControlEnv gates the device-dependent handler tests. test.sh sets it
// inside its network namespace, where interfaces can be created and the real
// WireGuard device paths behave deterministically.
const deviceControlEnv = "WGENROL_TEST_WIREGUARD_DEVICE_CONTROL"

// Package-local interface name, distinct from the other device-gated test
// families (wgenrol-test in internal/wireguard, wgenrol-serve in cmd) so
// parallel test binaries cannot collide in the shared namespace.
const apiIfname = "wgenrol-apitest"

func runIP(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

// newDeviceCtx is newStoreCtx plus a real WireGuard interface carrying a
// known address, so device introspection and IP allocation behave
// deterministically (the interface owns 10.203.0.1/24; allocation starts past
// the device address).
func newDeviceCtx(t *testing.T) *ServerContext {
	t.Helper()
	if os.Getenv(deviceControlEnv) == "" {
		t.Skipf("%s is not set: skipping device-dependent handler tests", deviceControlEnv)
	}
	runIP(t, "link", "add", apiIfname, "type", "wireguard")
	t.Cleanup(func() { runIP(t, "link", "del", apiIfname) })
	ctx := newStoreCtx(t)
	ifname := apiIfname
	ctx.Config.Wireguard.Ifname = &ifname
	runIP(t, "addr", "add", "10.203.0.1/24", "dev", apiIfname)
	return ctx
}

// newStoreCtx builds a ServerContext backed by a temporary SQLite store (no
// device is configured; handlers that would touch the WireGuard device only
// do so after the paths under test here have already completed).
func newStoreCtx(t *testing.T) *ServerContext {
	t.Helper()
	store, err := sqlite.Open(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	ifname := "wgenrol-test-iface"
	ctx := &ServerContext{
		Config: &config.WgEnrolConfig{},
	}
	ctx.Config.Wireguard.Ifname = &ifname
	ctx.Store = store
	ctx.Sessions = store
	return ctx
}

// seedSession stores a login session, the store-backed stand-in for seeding
// the former in-memory token map.
func seedSession(t *testing.T, ctx *ServerContext, token string, expiry time.Time) {
	t.Helper()
	if err := ctx.Sessions.CreateSession(token, expiry); err != nil {
		t.Fatal(err)
	}
}

// tempCertPair copies the repo's test cert/key into a temp dir and returns a
// ServerContext pointed at the copies, plus the two paths.
func tempCertPair(t *testing.T) (*ServerContext, string, string) {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	cb, err := os.ReadFile(filepath.Join("..", "..", "testdata", "test_cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	kb, err := os.ReadFile(filepath.Join("..", "..", "testdata", "test_key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, cb, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, kb, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := &ServerContext{Config: &config.WgEnrolConfig{}}
	ctx.Config.Server.Tls.CertFile = &certPath
	ctx.Config.Server.Tls.KeyFile = &keyPath
	return ctx, certPath, keyPath
}

// genSelfSigned creates a throwaway self-signed ECDSA cert/key pair (PEM).
func genSelfSigned(t *testing.T, serial int64) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "test"},
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
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
