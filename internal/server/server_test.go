package server

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"thebasstoon.com/wgenrol/internal/config"
)

func TestGetCertificateMatching(t *testing.T) {
	ctx, _, _ := tempCertPair(t)
	if _, err := getCertificate(nil, ctx, &certCache{}); err != nil {
		t.Fatalf("matching pair failed to load: %v", err)
	}
}

// First load of a mismatched pair with an empty cache returns an error.
func TestGetCertificateMismatchNoCache(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	cb, _ := os.ReadFile(filepath.Join("..", "..", "testdata", "test_cert.pem"))
	os.WriteFile(certPath, cb, 0o644)
	os.WriteFile(keyPath, cb, 0o644) // cert bytes where a key belongs
	ctx := &config.ServerContext{Config: &config.WgEnrolConfig{}}
	ctx.Config.Server.Tls.CertFile = &certPath
	ctx.Config.Server.Tls.KeyFile = &keyPath
	if _, err := getCertificate(nil, ctx, &certCache{}); err == nil {
		t.Fatal("expected error for mismatched pair with empty cache")
	}
}

func TestCertCacheHitAndReload(t *testing.T) {
	ctx, certPath, _ := tempCertPair(t)
	cache := &certCache{}
	c1, err := getCertificate(nil, ctx, cache)
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := getCertificate(nil, ctx, cache)
	if c1 != c2 {
		t.Fatal("expected cache hit (same *tls.Certificate)")
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(certPath, future, future); err != nil {
		t.Fatal(err)
	}
	c3, _ := getCertificate(nil, ctx, cache)
	if c3 == c1 {
		t.Fatal("expected reload after mtime change")
	}
}

// During a renewal window (cert/key temporarily mismatched) GetCertificate
// keeps serving the last-good cert, then reloads once the pair is consistent.
func TestCertCacheFallbackAndSelfHeal(t *testing.T) {
	ctx, _, keyPath := tempCertPair(t)
	certBytes, _ := os.ReadFile(*ctx.Config.Server.Tls.CertFile)
	keyBytes, _ := os.ReadFile(keyPath)
	cache := &certCache{}

	c1, err := getCertificate(nil, ctx, cache)
	if err != nil {
		t.Fatal(err)
	}

	// Mid-renewal: key no longer matches the cert; bump its mtime.
	os.WriteFile(keyPath, certBytes, 0o644)
	b := time.Now().Add(2 * time.Second)
	os.Chtimes(keyPath, b, b)
	c2, err := getCertificate(nil, ctx, cache)
	if err != nil || c2 != c1 {
		t.Fatalf("expected last-good fallback (err=%v, same=%v)", err, c2 == c1)
	}

	// A repeat call must still fall back (the failure must not be cached).
	c2b, err := getCertificate(nil, ctx, cache)
	if err != nil || c2b != c1 {
		t.Fatalf("expected continued fallback (err=%v, same=%v)", err, c2b == c1)
	}

	// Renewal completes: matching key restored, mtime bumped again.
	os.WriteFile(keyPath, keyBytes, 0o644)
	b2 := time.Now().Add(4 * time.Second)
	os.Chtimes(keyPath, b2, b2)
	c3, err := getCertificate(nil, ctx, cache)
	if err != nil {
		t.Fatal(err)
	}
	if c3 == c1 {
		t.Fatal("expected reload after renewal completed")
	}
}

func TestCertCacheConcurrent(t *testing.T) {
	ctx, _, _ := tempCertPair(t)
	cache := &certCache{}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 300; j++ {
				if _, err := getCertificate(nil, ctx, cache); err != nil {
					t.Errorf("GetCertificate: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// Underpins the renewal-window fallback: LoadX509KeyPair/X509KeyPair rejects a
// key that does not match the certificate.
func TestLoadX509KeyPairChecksMatch(t *testing.T) {
	certA, keyA := genSelfSigned(t, 1)
	_, keyB := genSelfSigned(t, 2)
	if _, err := tls.X509KeyPair(certA, keyA); err != nil {
		t.Fatalf("matching pair rejected: %v", err)
	}
	if _, err := tls.X509KeyPair(certA, keyB); err == nil {
		t.Fatal("expected mismatch to be rejected")
	}
}
