package main

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
)

// bcrypt hash of the password "password" (matches testfiles/test_config.yaml).
const testPasswordHash = "$2a$08$noE9l0k/bSRj0cyRaVsDsue4L2WEmHP9pHxfGOJ026xEttfFn3TFq"

// validKey returns a syntactically valid (32-byte) WireGuard key in std base64.
func validKey() string { return base64.StdEncoding.EncodeToString(make([]byte, 32)) }

// writeConf writes a minimal [Interface] config plus the given peer block to a
// temp file and returns its path.
func writeConf(t *testing.T, peerBlock string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "wg.conf")
	conf := "[Interface]\nPrivateKey = " + validKey() + "\nAddress = 10.64.0.1/24\nListenPort = 51820\n\n" + peerBlock
	if err := os.WriteFile(p, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// prefixes parses CIDR strings into a []netip.Prefix.
func prefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// newLoginCtx builds a ServerContext with a single admin user (admin/"password").
func newLoginCtx() *ServerContext {
	ctx := &ServerContext{
		Config:             &WgEnrolConfig{},
		ValidSessionTokens: map[string]time.Time{},
	}
	ctx.Config.Admin.Users = map[string]string{"admin": testPasswordHash}
	return ctx
}

// tempCertPair copies the repo's test cert/key into a temp dir and returns a
// ServerContext pointed at the copies, plus the two paths.
func tempCertPair(t *testing.T) (*ServerContext, string, string) {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	cb, err := os.ReadFile(filepath.Join("testfiles", "test_cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	kb, err := os.ReadFile(filepath.Join("testfiles", "test_key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, cb, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, kb, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := &ServerContext{Config: &WgEnrolConfig{}}
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
