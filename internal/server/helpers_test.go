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
	"path/filepath"
	"testing"
	"time"

	"thebasstoon.com/wgenrol/internal/config"
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

// newLoginCtx builds a ServerContext with a single admin user (admin/"password").
func newLoginCtx() *config.ServerContext {
	ctx := &config.ServerContext{
		Config:             &config.WgEnrolConfig{},
		ValidSessionTokens: map[string]time.Time{},
	}
	ctx.Config.Admin.Users = map[string]string{"admin": testPasswordHash}
	return ctx
}

// tempCertPair copies the repo's test cert/key into a temp dir and returns a
// ServerContext pointed at the copies, plus the two paths.
func tempCertPair(t *testing.T) (*config.ServerContext, string, string) {
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
	ctx := &config.ServerContext{Config: &config.WgEnrolConfig{}}
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
