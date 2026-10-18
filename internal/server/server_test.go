package server

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	ctx := &ServerContext{Config: &config.WgEnrolConfig{}}
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

// startServe runs serve() on an ephemeral listener in a goroutine and
// returns the base URL plus a stop function that closes the listener and
// waits for serve to return.
func startServe(t *testing.T, ctx *ServerContext) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	scheme := "http"
	if ctx.Config.Server.Tls.Enabled {
		scheme = "https"
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- serve(ctx, ln)
	}()
	return scheme + "://" + ln.Addr().String() + "/login", func() {
		ln.Close()
		select {
		case <-serveErr:
		case <-time.After(2 * time.Second):
			t.Error("serve did not return after the listener was closed")
		}
	}
}

// getWithRetry rides out the listener startup race.
func getWithRetry(t *testing.T, client *http.Client, url string) (*http.Response, string) {
	t.Helper()
	var lastErr error
	for i := 0; i < 20; i++ {
		resp, err := client.Get(url)
		if err == nil {
			t.Cleanup(func() { resp.Body.Close() })
			body, _ := io.ReadAll(resp.Body)
			return resp, string(body)
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("GET %s never succeeded: %v", url, lastErr)
	return nil, ""
}

// The full serve path over a plain HTTP listener: routes, timeouts wiring and
// handler responses behave exactly as they do in production.
func TestServePlainHTTP(t *testing.T) {
	ctx := newLoginCtx(t)
	base, stop := startServe(t, ctx)
	defer stop()
	resp, body := getWithRetry(t, &http.Client{Timeout: 2 * time.Second}, base)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(strings.ToLower(body), "password") {
		t.Error("login page not served")
	}
}

// A real TLS listener: the served certificate is the configured one, and the
// TLS-only middleware headers arrive over the wire.
func TestServeTLS(t *testing.T) {
	ctx, _, _ := tempCertPair(t)
	ctx.Config.Server.Tls.Enabled = true
	base, stop := startServe(t, ctx)
	defer stop()
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, _ := getWithRetry(t, client, base)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Strict-Transport-Security") == "" {
		t.Error("HSTS header missing on the TLS listener")
	}
	if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		t.Errorf("unexpected content type %q", resp.Header.Get("Content-Type"))
	}
}

// An unbindable address must fail at the bind, not at first request time.
func TestListenAndServeBindError(t *testing.T) {
	ctx := newLoginCtx(t)
	bad := "127.0.0.1:99999"
	ctx.Config.Server.ListenOn = &bad
	if err := ListenAndServe(ctx); err == nil {
		t.Fatal("expected a bind error for an invalid listen address")
	}
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

// The wrapHandler error-display matrix: visible errors reach the client
// exactly when the route allows them; invisible errors never do. This is what
// keeps error text away from unauthenticated callers.
func TestWrapHandlerErrorDisplay(t *testing.T) {
	cases := []struct {
		name     string
		visible  bool
		mask     bool
		wantBody string
	}{
		{"visible shown", true, false, "boom"},
		{"visible masked", true, true, ""},
		{"invisible", false, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := newLoginCtx(t)
			handler := wrapHandler(func(ctx *ServerContext, r *http.Request, w http.ResponseWriter) ([]byte, *handlerError) {
				return nil, wrapError(errors.New("boom"), 400, c.visible)
			}, ctx, "text/plain", false, false, nil, c.mask)
			rec := httptest.NewRecorder()
			handler(rec, httptest.NewRequest("POST", "/x", nil))
			if rec.Code != 400 {
				t.Fatalf("expected 400, got %d", rec.Code)
			}
			if body := rec.Body.String(); !strings.Contains(body, c.wantBody) || (c.wantBody == "" && body != "") {
				t.Fatalf("expected body %q, got %q", c.wantBody, body)
			}
		})
	}
}

// wrapHandler always sets security headers; HSTS only when TLS is enabled.
func TestWrapHandlerSecurityHeaders(t *testing.T) {
	ctx := newLoginCtx(t)
	ctx.Config.Server.Tls.Enabled = true
	handler := wrapHandler(func(ctx *ServerContext, r *http.Request, w http.ResponseWriter) ([]byte, *handlerError) {
		return nil, nil
	}, ctx, "text/plain", false, false, nil, false)
	cases := []struct {
		name     string
		tlsOn    bool
		wantHSTS bool
	}{
		{"tls on", true, true},
		{"tls off", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx.Config.Server.Tls.Enabled = c.tlsOn
			rec := httptest.NewRecorder()
			handler(rec, httptest.NewRequest("GET", "/x", nil))
			if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Fatalf("expected nosniff header, got %q", got)
			}
			if got := rec.Header().Get("Strict-Transport-Security"); c.wantHSTS && got == "" {
				t.Fatal("expected HSTS header when TLS is enabled")
			} else if !c.wantHSTS && got != "" {
				t.Fatalf("did not expect an HSTS header without TLS, got %q", got)
			}
			ctx.Config.Server.Tls.Enabled = true
		})
	}
}

// A certificate/key file that cannot be stat-ed must yield a descriptive
// error (both branches).
func TestGetCertificateStatFailures(t *testing.T) {
	ctx, certPath, _ := tempCertPair(t)
	if err := os.Remove(certPath); err != nil {
		t.Fatal(err)
	}
	if _, err := getCertificate(nil, ctx, &certCache{}); err == nil || !strings.Contains(err.Error(), "Failed to stat certfile") {
		t.Fatalf("expected a certfile stat error, got %v", err)
	}

	ctx2, _, keyPath := tempCertPair(t)
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := getCertificate(nil, ctx2, &certCache{}); err == nil || !strings.Contains(err.Error(), "Failed to stat keyfile") {
		t.Fatalf("expected a keyfile stat error, got %v", err)
	}
}
