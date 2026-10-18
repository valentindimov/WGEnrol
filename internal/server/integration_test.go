package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"testing"

	"thebasstoon.com/wgenrol/internal/wireguard"
)

// deviceIntegrationServer gates the WireGuard-backed integration flow on
// device control and serves the production route table over real HTTP, with
// the real test interface (known address → deterministic allocation).
func deviceIntegrationServer(t *testing.T) (*httptest.Server, *ServerContext) {
	t.Helper()
	newDeviceCtx(t)
	ctx := newStoreCtx(t)
	ctx.Config.Admin.Users = map[string]string{"admin": testPasswordHash}
	ifname := apiIfname
	ctx.Config.Wireguard.Ifname = &ifname
	srv := httptest.NewServer(newServeMux(ctx))
	t.Cleanup(srv.Close)
	return srv, ctx
}

// newIntegrationServer serves the production route table over real HTTP
// without a WireGuard interface; usable for auth/masking/IP-filter flows
// that never reach a peer- or device-touching handler.
func newIntegrationServer(t *testing.T) (*httptest.Server, *ServerContext) {
	t.Helper()
	ctx := newStoreCtx(t)
	ctx.Config.Admin.Users = map[string]string{"admin": testPasswordHash}
	srv := httptest.NewServer(newServeMux(ctx))
	t.Cleanup(srv.Close)
	return srv, ctx
}

// clientWithoutRedirects surfaces redirects instead of following them, so
// tests can assert on them. Pass nil for a cookie-less client; the jar is
// unwrapped to avoid storing a typed-nil pointer in the CookieJar interface.
func clientWithoutRedirects(t *testing.T, jar *cookiejar.Jar) *http.Client {
	t.Helper()
	var cookieJar http.CookieJar
	if jar != nil {
		cookieJar = jar
	}
	return &http.Client{
		Jar: cookieJar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func jsonRequest(method, url string, body any) *http.Request {
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, url, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func do(t *testing.T, client *http.Client, req *http.Request) (*http.Response, string) {
	t.Helper()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	bodyBytes, _ := io.ReadAll(resp.Body)
	return resp, string(bodyBytes)
}

func assertStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("expected status %d, got %d", want, resp.StatusCode)
	}
}

// The complete happy-path lifecycle over real HTTP: login, invite creation,
// anonymous enrollment through the public link, admin management, deletion,
// logout.
func TestIntegrationFullFlow(t *testing.T) {
	deviceControl := os.Getenv(deviceControlEnv)
	if deviceControl == "" {
		t.Skipf("%s is not set: skipping the WireGuard-backed integration flow", deviceControlEnv)
	}
	srv, _ := deviceIntegrationServer(t)

	jar, _ := cookiejar.New(nil)
	admin := clientWithoutRedirects(t, jar)

	// Login
	resp, _ := do(t, admin, jsonRequest("POST", srv.URL+"/login", map[string]any{"Username": "admin", "Password": "password"}))
	assertStatus(t, resp, 200)

	// Admin page renders both tables
	resp, body := do(t, admin, jsonRequest("GET", srv.URL+"/", nil))
	assertStatus(t, resp, 200)
	if !bytes.Contains([]byte(body), []byte("Pending invites")) {
		t.Fatal("admin page lacks the pending table")
	}

	// Create a pending invite; the store knows only the hash, we keep the preimage
	preimage := make([]byte, 32)
	if _, err := rand.Read(preimage); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(preimage)
	hashKey := wireguard.Key(hash)
	resp, _ = do(t, admin, jsonRequest("POST", srv.URL+"/pending", map[string]any{"TokenHash": hashKey.String(), "Comment": "Eve"}))
	assertStatus(t, resp, 200)

	// Anonymous enrollment page fetch
	anon := clientWithoutRedirects(t, nil)
	resp, page := do(t, anon, jsonRequest("GET", srv.URL+"/peer/"+base64.RawURLEncoding.EncodeToString(preimage), nil))
	assertStatus(t, resp, 200)
	// A fresh interface reports the all-zero public key; the peer address
	// appears without its mask inside the JS template literal.
	zeroPubkey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, expected := range []string{zeroPubkey, "10.203.0.2"} {
		if !bytes.Contains([]byte(page), []byte(expected)) {
			t.Errorf("enrollment page lacks %q", expected)
		}
	}

	// Anonymous enrollment claims the invite
	newKey := wireguard.Key{11}
	psk := wireguard.Key{12}
	resp, _ = do(t, anon, jsonRequest("PUT", srv.URL+"/peer/"+base64.RawURLEncoding.EncodeToString(preimage),
		map[string]any{"NewPubKey": newKey.String(), "NewPSK": psk.String()}))
	assertStatus(t, resp, 200)

	// The peer now shows up for the admin; the invite link is consumed
	resp, body = do(t, admin, jsonRequest("GET", srv.URL+"/", nil))
	assertStatus(t, resp, 200)
	if !bytes.Contains([]byte(body), []byte("Eve")) {
		t.Error("enrolled peer not visible on the admin page")
	}
	resp, _ = do(t, anon, jsonRequest("GET", srv.URL+"/peer/"+base64.RawURLEncoding.EncodeToString(preimage), nil))
	assertStatus(t, resp, 404)

	// Peer rename via the admin API
	resp, _ = do(t, admin, jsonRequest("PUT", srv.URL+"/peer", map[string]any{"Pubkey": newKey.String(), "Comment": "Renamed"}))
	assertStatus(t, resp, 200)

	// A second pending entry: edit its IPs, then delete it
	preimage2 := make([]byte, 32)
	if _, err := rand.Read(preimage2); err != nil {
		t.Fatal(err)
	}
	hash2 := sha256.Sum256(preimage2)
	hash2Key := wireguard.Key(hash2)
	resp, _ = do(t, admin, jsonRequest("POST", srv.URL+"/pending", map[string]any{"TokenHash": hash2Key.String(), "Comment": "Two"}))
	assertStatus(t, resp, 200)
	resp, _ = do(t, admin, jsonRequest("PUT", srv.URL+"/pending/"+base64.RawURLEncoding.EncodeToString(hash2Key[:]),
		map[string]any{"Comment": "TwoEdited", "AllowedIPs": []string{"10.203.0.9/32"}}))
	assertStatus(t, resp, 200)
	_, body = do(t, admin, jsonRequest("GET", srv.URL+"/", nil))
	if !bytes.Contains([]byte(body), []byte("TwoEdited")) {
		t.Error("edited pending entry not visible")
	}
	// Overlapping AllowedIPs must be rejected end-to-end (the enrolled peer
	// owns 10.203.0.2/32)
	resp, _ = do(t, admin, jsonRequest("PUT", srv.URL+"/pending/"+base64.RawURLEncoding.EncodeToString(hash2Key[:]),
		map[string]any{"Comment": "TwoEdited", "AllowedIPs": []string{"10.203.0.2/32"}}))
	assertStatus(t, resp, 400)
	resp, _ = do(t, admin, jsonRequest("DELETE", srv.URL+"/pending/"+base64.RawURLEncoding.EncodeToString(hash2Key[:]), nil))
	assertStatus(t, resp, 200)

	// Peer deletion pushes the remaining (empty) list to the device
	resp, _ = do(t, admin, jsonRequest("DELETE", srv.URL+"/peer/"+base64.RawURLEncoding.EncodeToString(newKey[:]), nil))
	assertStatus(t, resp, 200)
	_, body = do(t, admin, jsonRequest("GET", srv.URL+"/", nil))
	if bytes.Contains([]byte(body), []byte("Renamed")) {
		t.Error("deleted peer still visible on the admin page")
	}

	// After logout the admin surface is unreachable again
	resp, _ = do(t, admin, jsonRequest("POST", srv.URL+"/logout", nil))
	assertStatus(t, resp, 200)
	resp, _ = do(t, admin, jsonRequest("GET", srv.URL+"/", nil))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected a redirect after logout, got %d", resp.StatusCode)
	}
}

// Unauthenticated requests are redirected to /login and unauthenticated
// enrollment misses are masked (no error text leaks).
func TestIntegrationUnauthenticated(t *testing.T) {
	srv, _ := newIntegrationServer(t)
	anon := clientWithoutRedirects(t, nil)

	resp, _ := do(t, anon, jsonRequest("GET", srv.URL+"/", nil))
	if resp.StatusCode != 302 || !bytes.Contains([]byte(resp.Header.Get("Location")), []byte("/login")) {
		t.Fatalf("expected redirect to /login, got %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, _ = do(t, anon, jsonRequest("POST", srv.URL+"/pending", map[string]any{"TokenHash": wireguard.Key{1}.String()}))
	if resp.StatusCode != 302 {
		t.Fatalf("expected redirect for POST /pending, got %d", resp.StatusCode)
	}
	resp, body := do(t, anon, jsonRequest("GET", srv.URL+"/peer/"+base64.RawURLEncoding.EncodeToString(make([]byte, 32)), nil))
	if resp.StatusCode != 404 || body != "" {
		t.Fatalf("expected masked 404 with empty body, got %d %q", resp.StatusCode, body)
	}
	// Login errors are visible by design so users see what went wrong.
	resp, body = do(t, anon, jsonRequest("POST", srv.URL+"/login", map[string]any{"Username": "admin", "Password": "wrong"}))
	if resp.StatusCode != 401 || !bytes.Contains([]byte(body), []byte("Wrong username or password")) {
		t.Fatalf("expected visible 401, got %d %q", resp.StatusCode, body)
	}
}

// The admin IP allowlist gates every wrapped route, HTTP status 401.
func TestIntegrationIpFilter(t *testing.T) {
	ctx := newStoreCtx(t)
	ctx.Config.Admin.Users = map[string]string{"admin": testPasswordHash}
	ctx.AdminIpFilter = prefixes("10.99.0.0/16")
	srv := httptest.NewServer(newServeMux(ctx))
	t.Cleanup(srv.Close)

	client := clientWithoutRedirects(t, nil)
	resp, _ := do(t, client, jsonRequest("GET", srv.URL+"/login", nil))
	assertStatus(t, resp, 401)
	resp, _ = do(t, client, jsonRequest("GET", srv.URL+"/", nil))
	assertStatus(t, resp, 401)
	resp, _ = do(t, client, jsonRequest("POST", srv.URL+"/pending", map[string]any{"TokenHash": wireguard.Key{1}.String()}))
	assertStatus(t, resp, 401)
}
