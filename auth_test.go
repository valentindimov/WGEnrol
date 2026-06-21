package main

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

// Concurrent authenticated requests each write ValidSessionTokens (sliding
// expiry) inside AuthenticateRequest; wrapHandler's mutex must serialize that
// against login/logout-style writers. Meaningful under -race, but a regression
// that drops the lock also trips the runtime "concurrent map writes" fatal.
func TestWrapHandlerConcurrency(t *testing.T) {
	tok := "TESTTOKEN000000000000000000"
	ctx := &ServerContext{
		Config:             &WgEnrolConfig{},
		ValidSessionTokens: map[string]time.Time{tok: time.Now().Add(time.Hour)},
	}
	authed := wrapHandler(func(c *ServerContext, r *http.Request, w http.ResponseWriter) ([]byte, *HandlerError) {
		return nil, nil
	}, ctx, "text/plain", true, true, nil, false)
	writer := wrapHandler(func(c *ServerContext, r *http.Request, w http.ResponseWriter) ([]byte, *HandlerError) {
		c.ValidSessionTokens["other"] = time.Now().Add(time.Hour)
		delete(c.ValidSessionTokens, "other")
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
			for j := 0; j < 1000; j++ {
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
			for j := 0; j < 1000; j++ {
				writer(httptest.NewRecorder(), httptest.NewRequest("POST", "/x", nil))
			}
		}()
	}
	wg.Wait()
}

// Login must be reachable as wired (authenticated=false): no pre-existing
// session should be required to authenticate.
func TestLoginReachable(t *testing.T) {
	ctx := newLoginCtx()
	login := wrapHandler(handlePostLogin, ctx, "text/plain", false, true, nil, false)
	req := httptest.NewRequest("POST", "/login", strings.NewReader(`{"Username":"admin","Password":"password"}`))
	req.RemoteAddr = "127.0.0.1:5555"
	rec := httptest.NewRecorder()
	login(rec, req)
	if rec.Code != http.StatusOK || len(ctx.ValidSessionTokens) != 1 {
		t.Fatalf("valid creds did not authenticate (status=%d, tokens=%d)", rec.Code, len(ctx.ValidSessionTokens))
	}
}

func TestUnknownUserRejected(t *testing.T) {
	ctx := newLoginCtx()
	req := httptest.NewRequest("POST", "/login", strings.NewReader(`{"Username":"nobody","Password":"x"}`))
	_, herr := handlePostLogin(ctx, req, httptest.NewRecorder())
	if herr == nil || len(ctx.ValidSessionTokens) != 0 {
		t.Fatalf("unknown user not rejected (herr=%v, tokens=%d)", herr, len(ctx.ValidSessionTokens))
	}
}

func TestWrongPasswordRejected(t *testing.T) {
	ctx := newLoginCtx()
	req := httptest.NewRequest("POST", "/login", strings.NewReader(`{"Username":"admin","Password":"wrong"}`))
	_, herr := handlePostLogin(ctx, req, httptest.NewRecorder())
	if herr == nil || len(ctx.ValidSessionTokens) != 0 {
		t.Fatalf("wrong password accepted (herr=%v, tokens=%d)", herr, len(ctx.ValidSessionTokens))
	}
}

func TestCorrectLoginSucceeds(t *testing.T) {
	ctx := newLoginCtx()
	req := httptest.NewRequest("POST", "/login", strings.NewReader(`{"Username":"admin","Password":"password"}`))
	_, herr := handlePostLogin(ctx, req, httptest.NewRecorder())
	if herr != nil || len(ctx.ValidSessionTokens) != 1 {
		t.Fatalf("correct login failed (herr=%v, tokens=%d)", herr, len(ctx.ValidSessionTokens))
	}
}

// The admin ipFilter must gate /login (off-allowlist blocked, on-allowlist OK).
func TestLoginIPFiltered(t *testing.T) {
	ctx := newLoginCtx()
	ctx.AdminIpFilter = prefixes("192.168.0.0/16")
	login := wrapHandler(handlePostLogin, ctx, "text/plain", false, true, nil, false)

	off := httptest.NewRequest("POST", "/login", strings.NewReader(`{"Username":"admin","Password":"password"}`))
	off.RemoteAddr = "9.9.9.9:5555"
	recOff := httptest.NewRecorder()
	login(recOff, off)
	if recOff.Code != http.StatusUnauthorized || len(ctx.ValidSessionTokens) != 0 {
		t.Fatalf("off-allowlist login not blocked (status=%d, tokens=%d)", recOff.Code, len(ctx.ValidSessionTokens))
	}

	on := httptest.NewRequest("POST", "/login", strings.NewReader(`{"Username":"admin","Password":"password"}`))
	on.RemoteAddr = "192.168.1.10:5555"
	recOn := httptest.NewRecorder()
	login(recOn, on)
	if recOn.Code != http.StatusOK || len(ctx.ValidSessionTokens) != 1 {
		t.Fatalf("on-allowlist login failed (status=%d, tokens=%d)", recOn.Code, len(ctx.ValidSessionTokens))
	}
}

// An admin route must be blocked by the ipFilter even with a valid session.
func TestAdminRouteIPFiltered(t *testing.T) {
	ctx := newLoginCtx()
	ctx.AdminIpFilter = prefixes("192.168.0.0/16")
	tok := "TOKENVALUE000000000000000000"
	ctx.ValidSessionTokens[tok] = time.Now().Add(time.Hour)
	authed := wrapHandler(func(c *ServerContext, r *http.Request, w http.ResponseWriter) ([]byte, *HandlerError) {
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
	ctx := newLoginCtx()
	tok := "TOKENVALUE000000000000000000"
	ctx.ValidSessionTokens[tok] = time.Now().Add(time.Hour)
	reached := false
	authed := wrapHandler(func(c *ServerContext, r *http.Request, w http.ResponseWriter) ([]byte, *HandlerError) {
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
	ctx := newLoginCtx()
	authed := wrapHandler(func(c *ServerContext, r *http.Request, w http.ResponseWriter) ([]byte, *HandlerError) {
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
	ctx := newLoginCtx()
	login := wrapHandler(handlePostLogin, ctx, "text/plain", false, true, nil, false)
	big := bytes.Repeat([]byte("a"), 2*1024*1024) // 2 MB > 1 MB cap
	req := httptest.NewRequest("POST", "/login", bytes.NewReader(big))
	req.RemoteAddr = "127.0.0.1:5555"
	rec := httptest.NewRecorder()
	login(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized body, got %d", rec.Code)
	}
	if len(ctx.ValidSessionTokens) != 0 {
		t.Fatal("oversized request must not authenticate")
	}
}
