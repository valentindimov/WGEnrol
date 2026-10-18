package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/smtp"
	"strings"
	"testing"
	"time"

	"thebasstoon.com/wgenrol/internal/config"
	"thebasstoon.com/wgenrol/internal/storage"
	"thebasstoon.com/wgenrol/internal/wireguard"
)

// computeClientConfigAllowedIPs builds the client's Address from the
// intersection of the peer's allowed IPs and the device's own subnets.
func TestComputeClientConfigAllowedIPs(t *testing.T) {
	cases := []struct {
		name     string
		peerIPs  []string
		devNets  []string
		expected string
		wantErr  bool
	}{
		{"v4 dual-subnet", []string{"10.64.0.2/32", "10.64.1.2/32"}, []string{"10.64.0.1/24", "10.64.1.1/24"}, "10.64.0.2/24,10.64.1.2/24", false},
		{"single subnet", []string{"10.64.0.5/32"}, []string{"10.64.0.1/24"}, "10.64.0.5/24", false},
		{"ipv6", []string{"fd00::2/128"}, []string{"fd00::1/64"}, "fd00::2/64", false},
		{"empty intersection errors", []string{"192.168.99.5/32"}, []string{"10.64.0.1/24"}, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := computeClientConfigAllowedIPs(prefixes(c.peerIPs...), prefixes(c.devNets...))
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", *got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if *got != c.expected {
				t.Errorf("got %q, want %q", *got, c.expected)
			}
		})
	}
}

func TestGetFirstIPInNetwork(t *testing.T) {
	cases := []struct{ in, want string }{
		{"10.64.0.2/32", "10.64.0.2"}, // host route -> itself
		{"10.64.0.0/24", "10.64.0.1"}, // subnet -> first host (skips network addr)
		{"fd00::/64", "fd00::1"},      // ipv6 subnet -> first host
		{"fd00::5/128", "fd00::5"},    // ipv6 host route -> itself
	}
	for _, c := range cases {
		if got := getFirstIPInNetwork(netip.MustParsePrefix(c.in)); got.String() != c.want {
			t.Errorf("getFirstIPInNetwork(%s) = %s, want %s", c.in, got.String(), c.want)
		}
	}
}

// urlKey encodes a Key into the base64url-no-padding form used in path values.
func urlKey(key wireguard.Key) string {
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(key[:])
}

// handleCreatePending must reject UserEmail values containing CRLF (SMTP
// header injection) before any mail is sent. The email check runs before the
// store/driver are touched, so no WireGuard device is needed.
func TestCreatePendingRejectsEmailInjection(t *testing.T) {
	payloads := []string{
		"a@b.com\r\nBcc: attacker@y.com",
		"a@b.com\nBcc: attacker@y.com",
		"a@b.com\r\nSubject: hijacked",
		"not-an-email",
	}
	for _, email := range payloads {
		ctx := &ServerContext{Config: &config.WgEnrolConfig{}}
		body, _ := json.Marshal(map[string]any{
			"TokenHash":        validKey(),
			"Comment":          "x",
			"UserEmail":        email,
			"RegistrationLink": "http://example/",
		})
		req := httptest.NewRequest("POST", "/pending", bytes.NewReader(body))
		_, herr := handleCreatePending(ctx, req, httptest.NewRecorder())
		if herr == nil || herr.status != 400 {
			t.Errorf("email %q: expected 400, got %v", email, herr)
		}
	}
}

// A malformed preimage hash must be rejected before the device is touched.
func TestCreatePendingRejectsInvalidTokenHash(t *testing.T) {
	ctx := newStoreCtx(t)
	body, _ := json.Marshal(map[string]any{"TokenHash": "not!base64!", "Comment": "x"})
	req := httptest.NewRequest("POST", "/pending", bytes.NewReader(body))
	_, herr := handleCreatePending(ctx, req, httptest.NewRecorder())
	if herr == nil || herr.status != 400 {
		t.Fatalf("expected 400 for invalid hash, got %v", herr)
	}
}

// A repeated preimage hash must fail before the (device-dependent) allocation.
func TestCreatePendingRejectsDuplicate(t *testing.T) {
	ctx := newStoreCtx(t)
	hash := wireguard.Key{7}
	if err := ctx.Store.CreatePendingPeer(wireguard.PendingPeer{
		TokenHash:  hash,
		Comment:    "First",
		AllowedIps: prefixes("10.61.0.2/32"),
		CreatedAt:  time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"TokenHash": hash.String(), "Comment": "Second"})
	req := httptest.NewRequest("POST", "/pending", bytes.NewReader(body))
	_, herr := handleCreatePending(ctx, req, httptest.NewRecorder())
	if herr == nil || herr.status != 400 {
		t.Fatalf("expected 400 for duplicate pending enrollment, got %v", herr)
	}
}

// An email invitation requires a registration link in the same request.
func TestCreatePendingRequiresRegistrationLink(t *testing.T) {
	ctx := &ServerContext{Config: &config.WgEnrolConfig{}}
	body, _ := json.Marshal(map[string]any{"TokenHash": validKey(), "Comment": "x", "UserEmail": "a@b.com"})
	req := httptest.NewRequest("POST", "/pending", bytes.NewReader(body))
	_, herr := handleCreatePending(ctx, req, httptest.NewRecorder())
	if herr == nil || herr.status != 400 {
		t.Fatalf("expected 400 for missing registration link, got %v", herr)
	}
}

func TestEditPeerComment(t *testing.T) {
	ctx := newStoreCtx(t)
	peer := wireguard.WgPeer{Pubkey: wireguard.Key{3}, Comment: "Old", AllowedIps: prefixes("10.64.0.2/32")}
	if err := ctx.Store.CreatePeer(peer); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"Pubkey": peer.Pubkey.String(), "Comment": "New"})
	req := httptest.NewRequest("PUT", "/peer", bytes.NewReader(body))
	_, herr := handleEditPeer(ctx, req, httptest.NewRecorder())
	if herr != nil {
		t.Fatalf("edit failed: %v", herr)
	}
	got, ok, _ := ctx.Store.GetPeer(peer.Pubkey)
	if !ok || got.Comment != "New" {
		t.Fatalf("comment not updated: %q ok=%v", got.Comment, ok)
	}
}

func TestEditPeerNotFound(t *testing.T) {
	ctx := newStoreCtx(t)
	body, _ := json.Marshal(map[string]any{"Pubkey": wireguard.Key{8}.String(), "Comment": "x"})
	req := httptest.NewRequest("PUT", "/peer", bytes.NewReader(body))
	_, herr := handleEditPeer(ctx, req, httptest.NewRecorder())
	if herr == nil || herr.status != 404 {
		t.Fatalf("expected 404 for unknown peer, got %v", herr)
	}
}

func TestEditPeerRejectsInvalidKey(t *testing.T) {
	ctx := newStoreCtx(t)
	body, _ := json.Marshal(map[string]any{"Pubkey": "not!base64!", "Comment": "x"})
	req := httptest.NewRequest("PUT", "/peer", bytes.NewReader(body))
	_, herr := handleEditPeer(ctx, req, httptest.NewRecorder())
	if herr == nil || herr.status != 400 {
		t.Fatalf("expected 400 for invalid key, got %v", herr)
	}
}

func TestEditPending(t *testing.T) {
	ctx := newStoreCtx(t)
	entry := wireguard.PendingPeer{
		TokenHash:  wireguard.Key{9},
		Comment:    "Old",
		AllowedIps: prefixes("10.62.0.2/32"),
		CreatedAt:  time.Now(),
	}
	if err := ctx.Store.CreatePendingPeer(entry); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"Comment":    "New",
		"AllowedIPs": []string{"10.62.0.9/32", " fd00::9/128 "},
	})
	req := httptest.NewRequest("PUT", "/pending/"+urlKey(entry.TokenHash), bytes.NewReader(body))
	req.SetPathValue("tokenHash", urlKey(entry.TokenHash))
	_, herr := handleEditPending(ctx, req, httptest.NewRecorder())
	if herr != nil {
		t.Fatalf("pending edit failed: %v", herr)
	}
	got, ok, _ := ctx.Store.GetPendingPeer(entry.TokenHash)
	if !ok || got.Comment != "New" || len(got.AllowedIps) != 2 || got.AllowedIps[0].String() != "10.62.0.9/32" || got.AllowedIps[1].String() != "fd00::9/128" {
		t.Fatalf("pending not updated correctly: %+v ok=%v", got, ok)
	}
}

func TestEditPendingErrorPaths(t *testing.T) {
	cases := []struct {
		name       string
		seedPeer   bool
		targetHash *wireguard.Key
		body       map[string]any
		wantStatus int
	}{
		{
			name:       "unknown pending enrollment",
			body:       map[string]any{"Comment": "x", "AllowedIPs": []string{"10.62.0.9/32"}},
			targetHash: &wireguard.Key{50},
			wantStatus: 404,
		},
		{
			name:       "invalid CIDR",
			body:       map[string]any{"Comment": "x", "AllowedIPs": []string{"not-a-cidr"}},
			wantStatus: 400,
		},
		{
			name:       "empty AllowedIPs",
			body:       map[string]any{"Comment": "x", "AllowedIPs": []string{}},
			wantStatus: 400,
		},
		{
			name:       "overlap with an existing peer",
			seedPeer:   true,
			body:       map[string]any{"Comment": "x", "AllowedIPs": []string{"10.60.0.7/32"}},
			wantStatus: 400,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := newStoreCtx(t)
			entry := wireguard.PendingPeer{
				TokenHash:  wireguard.Key{9},
				Comment:    "Old",
				AllowedIps: prefixes("10.62.0.2/32"),
				CreatedAt:  time.Now(),
			}
			if err := ctx.Store.CreatePendingPeer(entry); err != nil {
				t.Fatal(err)
			}
			if c.seedPeer {
				if err := ctx.Store.CreatePeer(wireguard.WgPeer{Pubkey: wireguard.Key{1}, Comment: "P", AllowedIps: prefixes("10.60.0.7/32")}); err != nil {
					t.Fatal(err)
				}
			}
			target := entry.TokenHash
			if c.targetHash != nil {
				target = *c.targetHash
			}
			body, _ := json.Marshal(c.body)
			req := httptest.NewRequest("PUT", "/pending/"+urlKey(target), bytes.NewReader(body))
			req.SetPathValue("tokenHash", urlKey(target))
			_, herr := handleEditPending(ctx, req, httptest.NewRecorder())
			if herr == nil || herr.status != c.wantStatus {
				t.Fatalf("expected %d, got %v", c.wantStatus, herr)
			}
		})
	}
}

func TestDeletePending(t *testing.T) {
	ctx := newStoreCtx(t)
	entry := wireguard.PendingPeer{
		TokenHash:  wireguard.Key{9},
		Comment:    "Old",
		AllowedIps: prefixes("10.62.0.2/32"),
		CreatedAt:  time.Now(),
	}
	if err := ctx.Store.CreatePendingPeer(entry); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("DELETE", "/pending/"+urlKey(entry.TokenHash), nil)
	req.SetPathValue("tokenHash", urlKey(entry.TokenHash))
	_, herr := handleDeletePending(ctx, req, httptest.NewRecorder())
	if herr != nil {
		t.Fatalf("delete failed: %v", herr)
	}
	if _, ok, _ := ctx.Store.GetPendingPeer(entry.TokenHash); ok {
		t.Fatal("pending entry still present after deletion")
	}
}

func TestDeletePendingNotFound(t *testing.T) {
	ctx := newStoreCtx(t)
	req := httptest.NewRequest("DELETE", "/pending/"+urlKey(wireguard.Key{66}), nil)
	req.SetPathValue("tokenHash", urlKey(wireguard.Key{66}))
	_, herr := handleDeletePending(ctx, req, httptest.NewRecorder())
	if herr == nil || herr.status != 404 {
		t.Fatalf("expected 404 for unknown pending enrollment, got %v", herr)
	}
}

func TestDeletePeerMissing(t *testing.T) {
	ctx := newStoreCtx(t)
	req := httptest.NewRequest("DELETE", "/peer/"+urlKey(wireguard.Key{77}), nil)
	req.SetPathValue("pubkey", urlKey(wireguard.Key{77}))
	_, herr := handleDeletePeer(ctx, req, httptest.NewRecorder())
	// The missing-peer error surfaces before any device is touched.
	if herr == nil || herr.status != 404 {
		t.Fatalf("expected 404 for unknown peer, got %v", herr)
	}
}

func TestGetPeerEnrolmentPageNotFound(t *testing.T) {
	ctx := newStoreCtx(t)
	req := httptest.NewRequest("GET", "/peer/x", nil)
	req.SetPathValue("token", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	_, herr := handleGetPeerEnrolmentPage(ctx, req, httptest.NewRecorder())
	if herr == nil || herr.status != 404 {
		t.Fatalf("expected 404 for unknown preimage, got %v", herr)
	}
}

func TestEnrolPeerNotFound(t *testing.T) {
	ctx := newStoreCtx(t)
	req := httptest.NewRequest("PUT", "/peer/x", strings.NewReader(`{"NewPubKey":"AAAA"}`))
	req.SetPathValue("token", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	_, herr := handleEnrolPeer(ctx, req, httptest.NewRecorder())
	if herr == nil || herr.status != 404 {
		t.Fatalf("expected 404 for unknown preimage, got %v", herr)
	}
}

// Enrollment with an invalid public key must fail before the store (and thus
// the device) is touched.
func TestEnrolPeerRejectsInvalidKey(t *testing.T) {
	ctx := newStoreCtx(t)
	preimage := make([]byte, 32)
	hash := sha256.Sum256(preimage)
	if err := ctx.Store.CreatePendingPeer(wireguard.PendingPeer{
		TokenHash: hash, Comment: "Pending", AllowedIps: prefixes("10.63.0.2/32"), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("PUT", "/peer/x", strings.NewReader(`{"NewPubKey":"THIS-IS-NOT-A-VALID-KEY"}`))
	req.SetPathValue("token", base64.RawURLEncoding.EncodeToString(preimage))
	_, herr := handleEnrolPeer(ctx, req, httptest.NewRecorder())
	if herr == nil || herr.status != 400 {
		t.Fatalf("expected 400 for invalid new pubkey, got %v", herr)
	}
	if _, ok, _ := ctx.Store.GetPendingPeer(hash); !ok {
		t.Fatal("pending entry must survive a failed enrollment attempt")
	}
}

// handleGetRoot renders both the peers table and the pending invites table.
func TestGetRootRendersBothTables(t *testing.T) {
	ctx := newStoreCtx(t)
	if err := ctx.Store.CreatePeer(wireguard.WgPeer{Pubkey: wireguard.Key{21}, Comment: "AlicePeer", AllowedIps: prefixes("10.64.0.2/32")}); err != nil {
		t.Fatal(err)
	}
	if err := ctx.Store.CreatePendingPeer(wireguard.PendingPeer{TokenHash: wireguard.Key{22}, Comment: "PendingBob", AllowedIps: prefixes("10.64.0.3/32"), CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	result, herr := handleGetRoot(ctx, req, httptest.NewRecorder())
	if herr != nil {
		t.Fatalf("root handler failed: %v", herr)
	}
	page := string(result)
	for _, expected := range []string{"Pending invites", "PendingPeersListTable", "AlicePeer", "PendingBob", "PeersListTable"} {
		if !strings.Contains(page, expected) {
			t.Errorf("rendered page does not contain %q", expected)
		}
	}
}

func TestHandleGetLogin(t *testing.T) {
	result, herr := handleGetLogin(newLoginCtx(t), httptest.NewRequest("GET", "/login", nil), httptest.NewRecorder())
	if herr != nil {
		t.Fatalf("login page failed: %v", herr)
	}
	if !strings.Contains(strings.ToLower(string(result)), "password") {
		t.Error("login page does not contain a password field")
	}
}

func TestHandlePostLogout(t *testing.T) {
	ctx := newLoginCtx(t)
	tok := "LOGOUTTOK0000000000000"
	seedSession(t, ctx, tok, time.Now().Add(time.Hour))
	req := httptest.NewRequest("POST", "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: base64.URLEncoding.EncodeToString([]byte(tok))})
	rec := httptest.NewRecorder()
	_, herr := handlePostLogout(ctx, req, rec)
	if herr != nil {
		t.Fatalf("logout failed: %v", herr)
	}
	if _, ok, err := ctx.Sessions.SessionExpiry(tok); err != nil || ok {
		t.Fatalf("session token was not deleted on logout: ok=%v err=%v", ok, err)
	}
	// Go clears cookies by writing an empty value (MaxAge=0 means "no Max-Age
	// attribute" in net/http); the server-side token deletion is the real logout.
	if cookie := rec.Header().Get("Set-Cookie"); !strings.Contains(cookie, "session=;") {
		t.Fatalf("logout did not clear the cookie: %q", cookie)
	}
	// Logout without a session must be harmless.
	if _, herr := handlePostLogout(ctx, httptest.NewRequest("POST", "/logout", nil), httptest.NewRecorder()); herr != nil {
		t.Fatalf("cookieless logout failed: %v", herr)
	}
}

// A path value that decodes but is not 32 bytes long must be rejected with a 400.
func TestPathValueWrongLengthRejected(t *testing.T) {
	ctx := newStoreCtx(t)
	short := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	req := httptest.NewRequest("DELETE", "/pending/"+short, nil)
	req.SetPathValue("tokenHash", short)
	_, herr := handleDeletePending(ctx, req, httptest.NewRecorder())
	if herr == nil || herr.status != 400 {
		t.Fatalf("expected 400 for a wrong-length path value, got %v", herr)
	}
}

// newClosedStoreCtx hands out a context whose store is already closed, turning
// every store operation into a failure. This unlocks the 500 branches of all
// handlers without needing a broken database.
func newClosedStoreCtx(t *testing.T) *ServerContext {
	t.Helper()
	ctx := newStoreCtx(t)
	if err := ctx.Store.Close(); err != nil {
		t.Fatal(err)
	}
	return ctx
}

func TestClosedStoreHandlersReturn500(t *testing.T) {
	cases := []struct {
		name string
		call func(ctx *ServerContext, t *testing.T) *handlerError
	}{
		{"get root", func(ctx *ServerContext, t *testing.T) *handlerError {
			_, herr := handleGetRoot(ctx, httptest.NewRequest("GET", "/", nil), httptest.NewRecorder())
			return herr
		}},
		{"edit peer", func(ctx *ServerContext, t *testing.T) *handlerError {
			body, _ := json.Marshal(map[string]any{"Pubkey": wireguard.Key{1}.String(), "Comment": "x"})
			_, herr := handleEditPeer(ctx, httptest.NewRequest("PUT", "/peer", bytes.NewReader(body)), httptest.NewRecorder())
			return herr
		}},
		{"delete peer", func(ctx *ServerContext, t *testing.T) *handlerError {
			req := httptest.NewRequest("DELETE", "/peer/"+urlKey(wireguard.Key{1}), nil)
			req.SetPathValue("pubkey", urlKey(wireguard.Key{1}))
			_, herr := handleDeletePeer(ctx, req, httptest.NewRecorder())
			return herr
		}},
		{"create pending", func(ctx *ServerContext, t *testing.T) *handlerError {
			body, _ := json.Marshal(map[string]any{"TokenHash": wireguard.Key{1}.String(), "Comment": "x"})
			_, herr := handleCreatePending(ctx, httptest.NewRequest("POST", "/pending", bytes.NewReader(body)), httptest.NewRecorder())
			return herr
		}},
		{"enrolment page", func(ctx *ServerContext, t *testing.T) *handlerError {
			req := httptest.NewRequest("GET", "/peer/x", nil)
			req.SetPathValue("token", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
			_, herr := handleGetPeerEnrolmentPage(ctx, req, httptest.NewRecorder())
			return herr
		}},
		{"enrol peer", func(ctx *ServerContext, t *testing.T) *handlerError {
			req := httptest.NewRequest("PUT", "/peer/x", strings.NewReader(`{"NewPubKey":"AAAA"}`))
			req.SetPathValue("token", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
			_, herr := handleEnrolPeer(ctx, req, httptest.NewRecorder())
			return herr
		}},
		{"edit pending", func(ctx *ServerContext, t *testing.T) *handlerError {
			body, _ := json.Marshal(map[string]any{"Comment": "x", "AllowedIPs": []string{"10.60.0.1/32"}})
			req := httptest.NewRequest("PUT", "/pending/"+urlKey(wireguard.Key{1}), bytes.NewReader(body))
			req.SetPathValue("tokenHash", urlKey(wireguard.Key{1}))
			_, herr := handleEditPending(ctx, req, httptest.NewRecorder())
			return herr
		}},
		{"delete pending", func(ctx *ServerContext, t *testing.T) *handlerError {
			req := httptest.NewRequest("DELETE", "/pending/"+urlKey(wireguard.Key{1}), nil)
			req.SetPathValue("tokenHash", urlKey(wireguard.Key{1}))
			_, herr := handleDeletePending(ctx, req, httptest.NewRecorder())
			return herr
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if herr := c.call(newClosedStoreCtx(t), t); herr == nil || herr.status != 500 {
				t.Fatalf("expected 500 for a failed store operation, got %v", herr)
			}
		})
	}
}

// Creating a pending enrollment allocates a free IP (excluding other pending
// entries) and must NOT touch the WireGuard device.
func TestCreatePendingHappy(t *testing.T) {
	ctx := newDeviceCtx(t)
	createPending := func(hash wireguard.Key, comment string) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"TokenHash": hash.String(), "Comment": comment})
		_, herr := handleCreatePending(ctx, httptest.NewRequest("POST", "/pending", bytes.NewReader(body)), httptest.NewRecorder())
		if herr != nil {
			t.Fatalf("create pending failed: %v", herr)
		}
	}
	createPending(wireguard.Key{1}, "Eve")
	createPending(wireguard.Key{2}, "Mallory")

	entry, ok, err := ctx.Store.GetPendingPeer(wireguard.Key{1})
	if err != nil || !ok {
		t.Fatalf("pending entry missing: ok=%v err=%v", ok, err)
	}
	if entry.Comment != "Eve" || len(entry.AllowedIps) != 1 || entry.AllowedIps[0].String() != "10.203.0.2/32" {
		t.Fatalf("allocated IPs wrong: %+v", entry)
	}
	if entry.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero")
	}
	entry, _, _ = ctx.Store.GetPendingPeer(wireguard.Key{2})
	if len(entry.AllowedIps) != 1 || entry.AllowedIps[0].String() != "10.203.0.3/32" {
		t.Fatalf("second pending entry must get the next free IP: %+v", entry)
	}
}

// The enrollment page renders the client configuration from the pending
// entry's AllowedIPs and the device's own data. A freshly created interface
// without a private key reports the all-zero public key.
func TestGetPeerEnrolmentPageHappy(t *testing.T) {
	ctx := newDeviceCtx(t)
	preimage := make([]byte, 32)
	if _, err := rand.Read(preimage); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(preimage)
	if err := ctx.Store.CreatePendingPeer(wireguard.PendingPeer{
		TokenHash: hash, Comment: "Eve", AllowedIps: prefixes("10.203.0.2/32"), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/peer/x", nil)
	req.SetPathValue("token", base64.RawURLEncoding.EncodeToString(preimage))
	result, herr := handleGetPeerEnrolmentPage(ctx, req, httptest.NewRecorder())
	if herr != nil {
		t.Fatalf("enrolment page failed: %v", herr)
	}
	page := string(result)
	// Inside the page's JS template literal the slash is regexp-escaped by
	// html/template; assert on the address without the mask part.
	zeroPubkey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, expected := range []string{zeroPubkey, "10.203.0.2", base64.RawURLEncoding.EncodeToString(preimage)} {
		if !strings.Contains(page, expected) {
			t.Errorf("enrolment page does not contain %q", expected)
		}
	}
}

// The full enrollment promotes the pending entry to a real peer in one step:
// entries carry over, the device receives the new peer, and the pending
// entry is gone.
func TestEnrolPeerHappy(t *testing.T) {
	ctx := newDeviceCtx(t)
	preimage := make([]byte, 32)
	if _, err := rand.Read(preimage); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(preimage)
	if err := ctx.Store.CreatePendingPeer(wireguard.PendingPeer{
		TokenHash: hash, Comment: "Carry", AllowedIps: prefixes("10.203.0.2/32"), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	newKey := wireguard.Key{9}
	psk := wireguard.Key{8}
	body, _ := json.Marshal(map[string]any{"NewPubKey": newKey.String(), "NewPSK": psk.String()})
	req := httptest.NewRequest("PUT", "/peer/x", bytes.NewReader(body))
	req.SetPathValue("token", base64.RawURLEncoding.EncodeToString(preimage))
	_, herr := handleEnrolPeer(ctx, req, httptest.NewRecorder())
	if herr != nil {
		t.Fatalf("enrollment failed: %v", herr)
	}

	if _, ok, _ := ctx.Store.GetPendingPeer(hash); ok {
		t.Fatal("pending entry not consumed on enrollment")
	}
	peer, ok, _ := ctx.Store.GetPeer(newKey)
	if !ok {
		t.Fatal("peer not created on enrollment")
	}
	if peer.Comment != "Carry" || peer.PresharedKey == nil || *peer.PresharedKey != psk ||
		len(peer.AllowedIps) != 1 || peer.AllowedIps[0].String() != "10.203.0.2/32" {
		t.Fatalf("peer fields mishandled during enrollment: %+v", peer)
	}
}

// Deleting a peer pushes the remaining (possibly empty) peer list to the device.
func TestDeletePeerHappy(t *testing.T) {
	ctx := newDeviceCtx(t)
	peer := wireguard.WgPeer{Pubkey: wireguard.Key{30}, Comment: "Gone", AllowedIps: prefixes("10.203.0.5/32")}
	if err := ctx.Store.CreatePeer(peer); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("DELETE", "/peer/"+urlKey(peer.Pubkey), nil)
	req.SetPathValue("pubkey", urlKey(peer.Pubkey))
	_, herr := handleDeletePeer(ctx, req, httptest.NewRecorder())
	if herr != nil {
		t.Fatalf("delete failed: %v", herr)
	}
	if _, ok, _ := ctx.Store.GetPeer(peer.Pubkey); ok {
		t.Fatal("peer still present after deletion")
	}
}

// failingStore delegates everything to a real store but fails selected
// operations, letting tests reach late-stage error branches that the
// closed-store trick cannot (its first query always fails).
type failingStore struct {
	storage.PeerStore
	failListPeers     bool
	failListPending   bool
	failCreatePending bool
}

func (s *failingStore) ListPeers() ([]wireguard.WgPeer, error) {
	if s.failListPeers {
		return nil, errors.New("ListPeers failed")
	}
	return s.PeerStore.ListPeers()
}

func (s *failingStore) ListPendingPeers() ([]wireguard.PendingPeer, error) {
	if s.failListPending {
		return nil, errors.New("ListPendingPeers failed")
	}
	return s.PeerStore.ListPendingPeers()
}

func (s *failingStore) CreatePendingPeer(peer wireguard.PendingPeer) error {
	if s.failCreatePending {
		return errors.New("CreatePendingPeer failed")
	}
	return s.PeerStore.CreatePendingPeer(peer)
}

// The 500 paths after the duplicate pre-check: IP allocation lists, the
// pending insert.
func TestCreatePendingStoreFailures(t *testing.T) {
	cases := []struct {
		name     string
		failures failingStore
	}{
		{"list peers", failingStore{failListPeers: true}},
		{"list pending", failingStore{failListPending: true}},
		{"create pending", failingStore{failCreatePending: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := newDeviceCtx(t)
			inner := ctx.Store
			stub := c.failures
			stub.PeerStore = inner
			ctx.Store = &stub
			body, _ := json.Marshal(map[string]any{"TokenHash": wireguard.Key{1}.String(), "Comment": "Eve"})
			_, herr := handleCreatePending(ctx, httptest.NewRequest("POST", "/pending", bytes.NewReader(body)), httptest.NewRecorder())
			if herr == nil || herr.status != 500 {
				t.Fatalf("expected 500 for a failed store operation, got %v", herr)
			}
		})
	}
}

// With no WireGuard interface present, invite creation fails with a masked
// 500 at the device introspection step.
func TestCreatePendingDeviceError(t *testing.T) {
	ctx := newStoreCtx(t) // ifname "wgenrol-test-iface" does not exist
	body, _ := json.Marshal(map[string]any{"TokenHash": wireguard.Key{2}.String(), "Comment": "Eve"})
	_, herr := handleCreatePending(ctx, httptest.NewRequest("POST", "/pending", bytes.NewReader(body)), httptest.NewRecorder())
	if herr == nil || herr.status != 500 {
		t.Fatalf("expected 500 for a failing device query, got %v", herr)
	}
}

// A handler-level enrollment whose device apply fails must roll back: the
// pending entry survives and no peer is created.
func TestEnrolPeerApplyFailureRollsBack(t *testing.T) {
	ctx := newStoreCtx(t) // no WireGuard interface named "wgenrol-test-iface"
	preimage := make([]byte, 32)
	if _, err := rand.Read(preimage); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(preimage)
	if err := ctx.Store.CreatePendingPeer(wireguard.PendingPeer{
		TokenHash: hash, Comment: "Eve", AllowedIps: prefixes("10.70.0.2/32"), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	newKey := wireguard.Key{9}
	body, _ := json.Marshal(map[string]any{"NewPubKey": newKey.String()})
	req := httptest.NewRequest("PUT", "/peer/x", bytes.NewReader(body))
	req.SetPathValue("token", base64.RawURLEncoding.EncodeToString(preimage))
	_, herr := handleEnrolPeer(ctx, req, httptest.NewRecorder())
	if herr == nil || herr.status != 500 {
		t.Fatalf("expected 500 for a failing device apply, got %v", herr)
	}
	if _, ok, _ := ctx.Store.GetPendingPeer(hash); !ok {
		t.Fatal("pending entry must survive a failed device apply")
	}
	if _, ok, _ := ctx.Store.GetPeer(newKey); ok {
		t.Fatal("no peer may be committed when the device apply fails")
	}
}

// The SMTP hook receives the composed invite mail; the handler responds
// before delivery, so the goroutine is observed via the hook's channel.
func TestCreatePendingSendsEmail(t *testing.T) {
	ctx := newDeviceCtx(t)
	host, user, password, from := "smtp.example.com", "u@example.com", "pw", "from@example.com"
	port := 587
	ctx.Config.Smtp.Enabled = true
	ctx.Config.Smtp.Host = &host
	ctx.Config.Smtp.Port = &port
	ctx.Config.Smtp.User = &user
	ctx.Config.Smtp.Password = &password
	ctx.Config.Smtp.From = &from
	sent := make(chan string, 1)
	ctx.SendMailFn = func(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
		sent <- fmt.Sprintf("%s|%s|%s|%s", addr, from, strings.Join(to, ","), string(msg))
		return nil
	}

	body, _ := json.Marshal(map[string]any{
		"TokenHash":        wireguard.Key{3}.String(),
		"Comment":          "Eve",
		"UserEmail":        "eve@corp.example",
		"RegistrationLink": "http://example/register",
	})
	_, herr := handleCreatePending(ctx, httptest.NewRequest("POST", "/pending", bytes.NewReader(body)), httptest.NewRecorder())
	if herr != nil {
		t.Fatalf("create failed: %v", herr)
	}

	select {
	case got := <-sent:
		fields := strings.SplitN(got, "|", 4)
		if fields[0] != "smtp.example.com:587" || fields[1] != "from@example.com" || fields[2] != "eve@corp.example" {
			t.Fatalf("email routing fields wrong: %q", got)
		}
		if !strings.Contains(fields[3], "Subject: [WgEnrol] Registration Link") ||
			!strings.Contains(fields[3], "http://example/register") {
			t.Fatalf("email body wrong: %q", fields[3])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the send-mail hook was not called")
	}
}

// A failing delivery must not affect the handler outcome; the error is only
// logged inside the goroutine.
func TestCreatePendingSendFailure(t *testing.T) {
	ctx := newDeviceCtx(t)
	host := "smtp.example.com"
	port := 587
	user, password, from := "u@example.com", "pw", "from@example.com"
	ctx.Config.Smtp.Enabled = true
	ctx.Config.Smtp.Host = &host
	ctx.Config.Smtp.Port = &port
	ctx.Config.Smtp.User = &user
	ctx.Config.Smtp.Password = &password
	ctx.Config.Smtp.From = &from
	sent := make(chan error, 1)
	ctx.SendMailFn = func(string, smtp.Auth, string, []string, []byte) error {
		sent <- errors.New("relay down")
		return errors.New("relay down")
	}
	body, _ := json.Marshal(map[string]any{
		"TokenHash":        wireguard.Key{4}.String(),
		"Comment":          "Eve",
		"UserEmail":        "eve@corp.example",
		"RegistrationLink": "http://example/register",
	})
	_, herr := handleCreatePending(ctx, httptest.NewRequest("POST", "/pending", bytes.NewReader(body)), httptest.NewRecorder())
	if herr != nil {
		t.Fatalf("create must succeed regardless of delivery: %v", herr)
	}
	select {
	case err := <-sent:
		if err == nil || err.Error() != "relay down" {
			t.Fatalf("hook should have propagated the delivery failure, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the send-mail hook was not called")
	}
}
