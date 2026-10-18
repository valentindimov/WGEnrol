package server

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Concurrent authenticated requests slide session expiry (a store write per
// request) inside authenticateRequest; wrapHandler's mutex must serialize
// that against login/logout-style writers. Meaningful under -race: a
// regression that drops the lock trips the single-connection store's
// serialized expectations and the runtime's concurrent-map guards. Iteration
// counts are lower than they used to be because every request now performs a
// real database write.
func TestWrapHandlerConcurrency(t *testing.T) {
	tok := "TESTTOKEN000000000000000000"
	ctx := newStoreCtx(t)
	seedSession(t, ctx, tok, time.Now().Add(time.Hour))
	authed := wrapHandler(func(c *ServerContext, r *http.Request, w http.ResponseWriter) ([]byte, *handlerError) {
		return nil, nil
	}, ctx, "text/plain", true, true, nil, false)
	writer := wrapHandler(func(c *ServerContext, r *http.Request, w http.ResponseWriter) ([]byte, *handlerError) {
		if err := c.Sessions.CreateSession("other", time.Now().Add(time.Minute)); err != nil {
			t.Errorf("writer create: %v", err)
			return nil, nil
		}
		if err := c.Sessions.DeleteSession("other"); err != nil {
			t.Errorf("writer delete: %v", err)
		}
		return nil, nil
	}, ctx, "text/plain", false, false, nil, false)

	mkReq := func() *http.Request {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "127.0.0.1:40000"
		req.AddCookie(&http.Cookie{Name: "session", Value: base64.URLEncoding.EncodeToString([]byte(tok))})
		return req
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				rec := httptest.NewRecorder()
				authed(rec, mkReq())
				if rec.Code != http.StatusOK {
					t.Errorf("expected 200 for valid session, got %d", rec.Code)
					return
				}
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				writer(httptest.NewRecorder(), httptest.NewRequest("POST", "/x", nil))
			}
		}()
	}
	wg.Wait()
}

// Login must be reachable as wired (authenticated=false): no pre-existing
// session should be required to authenticate.
func TestLoginReachable(t *testing.T) {
	ctx := newLoginCtx(t)
	login := wrapHandler(handlePostLogin, ctx, "text/plain", false, true, nil, false)
	req := httptest.NewRequest("POST", "/login", strings.NewReader(`{"Username":"admin","Password":"password"}`))
	req.RemoteAddr = "127.0.0.1:5555"
	rec := httptest.NewRecorder()
	login(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid creds did not authenticate (status=%d)", rec.Code)
	}
	tok := sessionCookieToken(t, rec)
	if _, ok, err := ctx.Sessions.SessionExpiry(tok); err != nil || !ok {
		t.Fatalf("login must persist a session in the store: ok=%v err=%v", ok, err)
	}
}

func TestUnknownUserRejected(t *testing.T) {
	ctx := newLoginCtx(t)
	req := httptest.NewRequest("POST", "/login", strings.NewReader(`{"Username":"nobody","Password":"x"}`))
	rec := httptest.NewRecorder()
	_, herr := handlePostLogin(ctx, req, rec)
	if herr == nil || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("unknown user must not receive a session cookie (herr=%v, cookies=%d)", herr, len(rec.Result().Cookies()))
	}
}

func TestWrongPasswordRejected(t *testing.T) {
	ctx := newLoginCtx(t)
	req := httptest.NewRequest("POST", "/login", strings.NewReader(`{"Username":"admin","Password":"wrong"}`))
	rec := httptest.NewRecorder()
	_, herr := handlePostLogin(ctx, req, rec)
	if herr == nil || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("wrong password must not receive a session cookie (herr=%v, cookies=%d)", herr, len(rec.Result().Cookies()))
	}
}

func TestCorrectLoginSucceeds(t *testing.T) {
	ctx := newLoginCtx(t)
	req := httptest.NewRequest("POST", "/login", strings.NewReader(`{"Username":"admin","Password":"password"}`))
	rec := httptest.NewRecorder()
	_, herr := handlePostLogin(ctx, req, rec)
	if herr != nil {
		t.Fatalf("correct login failed (herr=%v)", herr)
	}
	tok := sessionCookieToken(t, rec)
	expiry, ok, err := ctx.Sessions.SessionExpiry(tok)
	if err != nil || !ok {
		t.Fatalf("session not persisted: ok=%v err=%v", ok, err)
	}
	if !expiry.After(time.Now().Add(30 * time.Minute)) {
		t.Fatalf("session expiry should be about one hour out, got %v", expiry)
	}
}

// The admin ipFilter must gate /login (off-allowlist blocked, on-allowlist OK).
func TestLoginIPFiltered(t *testing.T) {
	ctx := newLoginCtx(t)
	ctx.AdminIpFilter = prefixes("192.168.0.0/16")
	login := wrapHandler(handlePostLogin, ctx, "text/plain", false, true, nil, false)

	off := httptest.NewRequest("POST", "/login", strings.NewReader(`{"Username":"admin","Password":"password"}`))
	off.RemoteAddr = "9.9.9.9:5555"
	recOff := httptest.NewRecorder()
	login(recOff, off)
	if recOff.Code != http.StatusUnauthorized || len(recOff.Result().Cookies()) != 0 {
		t.Fatalf("off-allowlist login not blocked (status=%d, cookies=%d)", recOff.Code, len(recOff.Result().Cookies()))
	}

	on := httptest.NewRequest("POST", "/login", strings.NewReader(`{"Username":"admin","Password":"password"}`))
	on.RemoteAddr = "192.168.1.10:5555"
	recOn := httptest.NewRecorder()
	login(recOn, on)
	if recOn.Code != http.StatusOK {
		t.Fatalf("on-allowlist login failed (status=%d)", recOn.Code)
	}
	if _, ok, _ := ctx.Sessions.SessionExpiry(sessionCookieToken(t, recOn)); !ok {
		t.Fatal("on-allowlist login did not persist a session")
	}
}

// An admin route must be blocked by the ipFilter even with a valid session.
func TestAdminRouteIPFiltered(t *testing.T) {
	ctx := newLoginCtx(t)
	ctx.AdminIpFilter = prefixes("192.168.0.0/16")
	tok := "TOKENVALUE000000000000000000"
	seedSession(t, ctx, tok, time.Now().Add(time.Hour))
	authed := wrapHandler(func(c *ServerContext, r *http.Request, w http.ResponseWriter) ([]byte, *handlerError) {
		return nil, nil
	}, ctx, "text/plain", true, true, nil, false)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "9.9.9.9:5556"
	req.AddCookie(&http.Cookie{Name: "session", Value: base64.URLEncoding.EncodeToString([]byte(tok))})
	rec := httptest.NewRecorder()
	authed(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected admin route blocked by IP filter, got %d", rec.Code)
	}
}

// A valid session on an allowlisted IP reaches the handler.
func TestAdminRouteAllowedWithSession(t *testing.T) {
	ctx := newLoginCtx(t)
	tok := "TOKENVALUE000000000000000000"
	seedSession(t, ctx, tok, time.Now().Add(time.Hour))
	reached := false
	authed := wrapHandler(func(c *ServerContext, r *http.Request, w http.ResponseWriter) ([]byte, *handlerError) {
		reached = true
		return nil, nil
	}, ctx, "text/plain", true, true, nil, false)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:5557"
	req.AddCookie(&http.Cookie{Name: "session", Value: base64.URLEncoding.EncodeToString([]byte(tok))})
	authed(httptest.NewRecorder(), req)
	if !reached {
		t.Fatal("handler not reached for a valid session")
	}
}

// A request without a session cookie is redirected to /login.
func TestNoSessionRedirects(t *testing.T) {
	ctx := newLoginCtx(t)
	authed := wrapHandler(func(c *ServerContext, r *http.Request, w http.ResponseWriter) ([]byte, *handlerError) {
		t.Fatal("handler should not run without a session")
		return nil, nil
	}, ctx, "text/plain", true, true, nil, false)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:5558"
	rec := httptest.NewRecorder()
	authed(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/login" {
		t.Fatalf("expected redirect to /login, got %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

// wrapHandler caps the request body (DoS guard); an oversized body must be
// rejected rather than read in full.
func TestBodySizeLimited(t *testing.T) {
	ctx := newLoginCtx(t)
	login := wrapHandler(handlePostLogin, ctx, "text/plain", false, true, nil, false)
	big := bytes.Repeat([]byte("a"), 2*1024*1024) // 2 MB > 1 MB cap
	req := httptest.NewRequest("POST", "/login", bytes.NewReader(big))
	req.RemoteAddr = "127.0.0.1:5555"
	rec := httptest.NewRecorder()
	login(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized body, got %d", rec.Code)
	}
}

// A session cookie whose value is not base64 yields a redirect, not a panic.
func TestAuthenticateRequestMalformedCookieRedirects(t *testing.T) {
	ctx := newLoginCtx(t)
	authed := wrapHandler(func(c *ServerContext, r *http.Request, w http.ResponseWriter) ([]byte, *handlerError) {
		t.Fatal("handler must not run")
		return nil, nil
	}, ctx, "text/plain", true, true, nil, false)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:40001"
	req.AddCookie(&http.Cookie{Name: "session", Value: "!!!garbage!!!"})
	rec := httptest.NewRecorder()
	authed(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/login" {
		t.Fatalf("expected redirect to /login, got %d", rec.Code)
	}
}

// An expired session is rejected with a redirect even though it exists in
// the store.
func TestAuthenticateRequestExpiredTokenRedirects(t *testing.T) {
	ctx := newLoginCtx(t)
	seedSession(t, ctx, "expired", time.Now().Add(-time.Minute))
	authed := wrapHandler(func(c *ServerContext, r *http.Request, w http.ResponseWriter) ([]byte, *handlerError) {
		t.Fatal("handler must not run")
		return nil, nil
	}, ctx, "text/plain", true, true, nil, false)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:40002"
	req.AddCookie(&http.Cookie{Name: "session", Value: base64.URLEncoding.EncodeToString([]byte("expired"))})
	rec := httptest.NewRecorder()
	authed(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected redirect for an expired token, got %d", rec.Code)
	}
}

// A valid session's sliding expiry is pushed forward on every authenticated
// request; the store must reflect the slide.
func TestAuthenticateRequestExtendsValidity(t *testing.T) {
	tok := "TOKEXT000000000000000000"
	ctx := newLoginCtx(t)
	seedSession(t, ctx, tok, time.Now().Add(time.Minute))
	authed := wrapHandler(func(c *ServerContext, r *http.Request, w http.ResponseWriter) ([]byte, *handlerError) {
		return nil, nil
	}, ctx, "text/plain", true, true, nil, false)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:40003"
	req.AddCookie(&http.Cookie{Name: "session", Value: base64.URLEncoding.EncodeToString([]byte(tok))})
	rec := httptest.NewRecorder()
	authed(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	expiry, ok, err := ctx.Sessions.SessionExpiry(tok)
	if err != nil || !ok {
		t.Fatalf("session expiry unreadable: ok=%v err=%v", ok, err)
	}
	if !expiry.After(time.Now().Add(30 * time.Minute)) {
		t.Fatalf("validity was not slid to a one-hour expiry, got %v", expiry)
	}
}

// Login prunes expired sessions (housekeeping hook); stale ones disappear.
func TestHandlePostLoginPrunesExpiredTokens(t *testing.T) {
	ctx := newLoginCtx(t)
	seedSession(t, ctx, "stale", time.Now().Add(-time.Hour))
	_, herr := handlePostLogin(ctx, httptest.NewRequest("POST", "/login", strings.NewReader(`{"Username":"admin","Password":"password"}`)), httptest.NewRecorder())
	if herr != nil {
		t.Fatalf("login failed: %v", herr)
	}
	if _, ok, err := ctx.Sessions.SessionExpiry("stale"); err != nil || ok {
		t.Fatalf("expired session must be pruned at login: ok=%v err=%v", ok, err)
	}
	// Second prune is a no-op: nothing else expired.
	if removed, err := ctx.Sessions.DeleteExpiredSessions(time.Now()); err != nil || removed != 0 {
		t.Fatalf("expected an empty second prune, got removed=%d err=%v", removed, err)
	}
}

// A malformed login body yields a visible 400 before any credential work.
func TestHandlePostLoginMalformedJSON(t *testing.T) {
	ctx := newLoginCtx(t)
	_, herr := handlePostLogin(ctx, httptest.NewRequest("POST", "/login", strings.NewReader("{bad")), httptest.NewRecorder())
	if herr == nil || herr.status != 400 || !strings.Contains(*herr.message, "Malformed") {
		t.Fatalf("expected 400 'Malformed request', got %v", herr)
	}
}

func TestGetSessionToken(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: base64.URLEncoding.EncodeToString([]byte("tok123"))})
	token, err := getSessionToken(req)
	if err != nil || token == nil || *token != "tok123" {
		t.Fatalf("valid session cookie rejected: %v %v", token, err)
	}

	req = httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "!!not-base64!!"})
	if _, err := getSessionToken(req); err == nil {
		t.Fatal("expected an error for a non-base64 cookie")
	}

	req = httptest.NewRequest("GET", "/", nil)
	if _, err := getSessionToken(req); err == nil {
		t.Fatal("expected an error for a missing session cookie")
	}
}

// An unparseable RemoteAddr must not crash the IP filter; it yields a 500.
func TestApplyIpFilterBadRemoteAddr(t *testing.T) {
	ctx := newLoginCtx(t)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "not-an-addrport"
	rec := httptest.NewRecorder()
	if err := applyIpFilter(req, rec, ctx); err == nil {
		t.Fatal("expected an error for a bad RemoteAddr")
	}
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "Internal Server Error") {
		t.Fatalf("expected 500 Internal Server Error, got %d %q", rec.Code, rec.Body.String())
	}
}

// sessionCookieToken extracts and decodes the session token from a handler's
// Set-Cookie response.
func sessionCookieToken(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	cookies := rec.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "session" && c.Value != "" {
			decoded, err := base64.URLEncoding.DecodeString(c.Value)
			if err != nil {
				t.Fatalf("cannot decode session cookie: %v", err)
			}
			return string(decoded)
		}
	}
	t.Fatalf("no session cookie set (cookies: %v)", cookies)
	return ""
}
