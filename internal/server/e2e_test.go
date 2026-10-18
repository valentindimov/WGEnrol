// Browser end-to-end tests: the inline JavaScript (dialog wiring, Web Crypto
// enrollment, QR rendering) is exercised by driving a real headless Chromium
// over the production route table. Gated on WGENROL_TEST_E2E_BROWSER
// (enabled by test.sh when a Chromium-family browser is installed) and on
// device control for all flows that touch peers. These tests add no Go
// coverage; their value is behavioral — they catch template/JS/API contract
// breakage that Go-side tests cannot see.
package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"fmt"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"

	"thebasstoon.com/wgenrol/internal/wireguard"
)

const browserGateEnv = "WGENROL_TEST_E2E_BROWSER"
const browserBinaryEnv = "WGENROL_TEST_E2E_CHROMIUM"

var browserBinaries = []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable"}

// browserExecPath is the E2E gate: it skips cleanly when the gate is unset,
// and fails hard when the gate was requested without a browser to run.
func browserExecPath(t *testing.T) string {
	t.Helper()
	if os.Getenv(browserGateEnv) == "" {
		t.Skipf("%s is not set: skipping browser E2E tests (enabled automatically by test.sh when a browser is installed)", browserGateEnv)
	}
	if path := os.Getenv(browserBinaryEnv); path != "" {
		return path
	}
	for _, candidate := range browserBinaries {
		if path, err := exec.LookPath(candidate); err == nil {
			return path
		}
	}
	t.Fatalf("%s is set but no browser is installed (looked for: %s). Install a Chromium-family browser, or point %s at its binary.",
		browserGateEnv, strings.Join(browserBinaries, ", "), browserBinaryEnv)
	return ""
}

// newE2EBrowser starts an isolated headless browser with a fresh profile
// (no cookies between tests). No sandbox: we run as mapped root inside a
// userns-owned namespace, and Chromium's own sandbox refuses this setup.
func newE2EBrowser(t *testing.T) context.Context {
	t.Helper()
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(browserExecPath(t)),
		chromedp.Flag("no-sandbox", true),
	)
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	t.Cleanup(allocCancel)
	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	t.Cleanup(browserCancel)
	return browserCtx
}

// The enrolment page shows a blocking `window.confirm` on load (the invite is
// single-use); its error paths use blocking `window.alert`. Both are
// pre-answered via a document-start injection, which CDP registers per
// target: every new tab needs its own injection.
const confirmOverride = `window.confirm = () => true; window.alert = () => {};`

// newE2ETab opens a fresh tab, warm-started with an untimed first Run (per
// chromedp's contract, a timeout on the first Run's context would kill the
// whole browser) and the confirm override installed.
func newE2ETab(t *testing.T, browserCtx context.Context) context.Context {
	t.Helper()
	tabCtx, tabCancel := chromedp.NewContext(browserCtx)
	t.Cleanup(tabCancel)
	if _, err := chromedp.Run(tabCtx, chromedp.Navigate("about:blank")); err != nil {
		t.Fatalf("browser did not launch: %v", err)
	}
	if err := chromedp.Do(tabCtx, func(c context.Context, target *chromedp.Target) (chromedp.Void, error) {
		_, err := cdp.Call(c, target, page.AddScriptToEvaluateOnNewDocument,
			page.AddScriptToEvaluateOnNewDocumentParams{Source: confirmOverride})
		return chromedp.Void{}, err
	}); err != nil {
		t.Fatalf("cannot install the confirm override: %v", err)
	}
	return tabCtx
}

// This environment (headless Chrome in the netns, chromedp v0.21) has two
// unusable primitives: chromedp's input-event Click wedges indefinitely (the
// mouse-event dispatch never completes), and chromedp's Evaluate action
// wedges every subsequent query action on the same target. Everything else
// (Navigate, SendKeys, query-based waits, and plain cdp.Call evaluate) is
// fast and reliable, so all JS interaction below goes through custom
// cdp.Call actions.
func ptr(b bool) *bool { return &b }

func jsClick(sel string) chromedp.Action[chromedp.Void] {
	return func(c context.Context, target *chromedp.Target) (chromedp.Void, error) {
		// Settle before dispatching: calls issued while the browser is still
		// finishing a page transition's tail work (favicon/subresource loads
		// after a JS-initiated redirect) wedge the target's call queue in
		// this chromedp/headless combination — a ~1s brevity avoids it.
		select {
		case <-time.After(1 * time.Second):
		case <-c.Done():
			return chromedp.Void{}, c.Err()
		}
		return evalVoid(fmt.Sprintf(`document.querySelector(%q).click()`, sel))(c, target)
	}
}

// evalVoid evaluates an expression for its side effects.
func evalVoid(expr string) chromedp.Action[chromedp.Void] {
	return func(c context.Context, target *chromedp.Target) (chromedp.Void, error) {
		_, err := cdp.Call(c, target, runtime.Evaluate, runtime.EvaluateParams{
			Expression:    expr,
			ReturnByValue: ptr(true),
		})
		return chromedp.Void{}, err
	}
}

// evalString evaluates an expression returning a string value.
func evalString(expr string) chromedp.Action[string] {
	return func(c context.Context, target *chromedp.Target) (string, error) {
		result, err := cdp.Call(c, target, runtime.Evaluate, runtime.EvaluateParams{
			Expression:    expr,
			ReturnByValue: ptr(true),
		})
		if err != nil {
			return "", err
		}
		if result.ExceptionDetails != nil {
			return "", fmt.Errorf("evaluate failed: %s", result.ExceptionDetails.Text)
		}
		var value string
		if err := json.Unmarshal(result.Result.Value, &value); err != nil {
			return "", err
		}
		return value, nil
	}
}

// evalBool evaluates an expression returning a boolean value.
func evalBool(expr string) chromedp.Action[bool] {
	return func(c context.Context, target *chromedp.Target) (bool, error) {
		result, err := cdp.Call(c, target, runtime.Evaluate, runtime.EvaluateParams{
			Expression:    expr,
			ReturnByValue: ptr(true),
		})
		if err != nil {
			return false, err
		}
		if result.ExceptionDetails != nil {
			return false, fmt.Errorf("evaluate failed: %s", result.ExceptionDetails.Text)
		}
		var value bool
		if err := json.Unmarshal(result.Result.Value, &value); err != nil {
			return false, err
		}
		return value, nil
	}
}

// runWithTimeout runs steps with a derived per-step deadline; the tab context
// itself stays untimed, so a step failure never kills the browser.
func runWithTimeout(t *testing.T, what string, tabCtx context.Context, d time.Duration, steps ...chromedp.Action[chromedp.Void]) {
	t.Helper()
	actionCtx, cancel := context.WithTimeout(tabCtx, d)
	defer cancel()
	if err := chromedp.Do(actionCtx, steps...); err != nil {
		t.Fatalf("browser step %q failed: %v", what, err)
	}
}

// waitBodyContains polls for a page state after JS-triggered reloads. The
// checks run via JS evaluate, not via chromedp's query-poll actions: in this
// environment their element lookup wedges after a JS-initiated navigation
// (login's fetch+redirect, the dialog-confirm reload) replaces the runtime
// context, while evaluate is robust. chromedp query waits remain usable
// within a single document and after Navigate-command loads.
func waitBodyContains(t *testing.T, tabCtx context.Context, substr string) {
	t.Helper()
	// One poll context for the whole loop, cancelled once at the end: a
	// per-iteration timeout-cancel can hit while a poll call is still
	// resolving mid-navigation, which wedges all later calls on the target.
	pollCtx, cancel := context.WithTimeout(tabCtx, 25*time.Second)
	defer cancel()
	for {
		body, err := chromedp.Run(pollCtx, evalString(`document.body ? document.body.innerText : ""`))
		if err == nil && strings.Contains(body, substr) {
			return
		}
		if pollCtx.Err() != nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("the page never contained %q within 25 s", substr)
}

// waitVisibleJS polls until the named element exists and is on-screen (the
// dialog contents become visible when their <dialog> opens, buttons when
// their "hidden" class is removed). Evaluate-based per the environment notes.
func waitVisibleJS(t *testing.T, tabCtx context.Context, sel string) {
	t.Helper()
	pollCtx, cancel := context.WithTimeout(tabCtx, 20*time.Second)
	defer cancel()
	expr := fmt.Sprintf(`!!document.querySelector(%q) && (document.querySelector(%q).offsetParent !== null || document.querySelector(%q).getClientRects().length > 0)`, sel, sel, sel)
	for {
		visible, err := chromedp.Run(pollCtx, evalBool(expr))
		if err == nil && visible {
			return
		}
		if pollCtx.Err() != nil {
			t.Fatalf("element %q never became visible within 20 s", sel)
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// e2eLogin drives the browser through the login page onto the admin panel.
// Each step runs as its own Do: compound multi-step Do calls (navigation +
// input dispatch in one step) wedge indefinitely in this chromedp/headless
// combination, while sequential single-step calls are instant.
func e2eLogin(t *testing.T, tabCtx context.Context, baseURL string) {
	t.Helper()
	runWithTimeout(t, "navigate to login", tabCtx, 30*time.Second, chromedp.Navigate(baseURL+"/login"))
	runWithTimeout(t, "type username", tabCtx, 15*time.Second, chromedp.SendKeys("#UsernameInput", "admin"))
	runWithTimeout(t, "type password", tabCtx, 15*time.Second, chromedp.SendKeys("#PasswordInput", "password"))
	runWithTimeout(t, "submit login", tabCtx, 15*time.Second, jsClick("button"))
	// The redirect to "/" is JS-initiated: the page must be polled via JS
	// evaluate (a query wait would wedge in this environment), so "Pending
	// invites" on the admin panel is the login marker.
	waitBodyContains(t, tabCtx, "Pending invites")
}

// The simplest flow: real browser, real login page, JS-driven fetch + redirect.
func TestE2ELogin(t *testing.T) {
	browserExecPath(t)
	srv, _ := newIntegrationServer(t)
	tabCtx := newE2ETab(t, newE2EBrowser(t))
	e2eLogin(t, tabCtx, srv.URL)
}

// The Add-New dialog mints a registration link client-side (the raw token
// never leaves the browser) and its confirmation POSTs the token digest.
func TestE2ECreateInvite(t *testing.T) {
	browserExecPath(t)
	srv, _ := deviceIntegrationServer(t)
	tabCtx := newE2ETab(t, newE2EBrowser(t))
	e2eLogin(t, tabCtx, srv.URL)

	runWithTimeout(t, "open add dialog", tabCtx, 30*time.Second, jsClick("#AddNewPeerButton"))
	waitVisibleJS(t, tabCtx, "#AddPeerDialogRegistrationLink")
	link, err := chromedp.Run(tabCtx, evalString(`document.getElementById("AddPeerDialogRegistrationLink").innerText`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(link, srv.URL+"/peer/") || len(link) <= len(srv.URL+"/peer/") {
		t.Fatalf("the dialog did not produce a registration link: %q", link)
	}
	runWithTimeout(t, "confirm dialog", tabCtx, 30*time.Second,
		chromedp.SendKeys("#AddPeerDialogNameInput", "BrowserInvite"),
		jsClick("#AddPeerDialogSaveButton"),
	)
	// The tab reloads itself after the POST; the pending table must show it.
	waitBodyContains(t, tabCtx, "BrowserInvite")
}

// The full enrollment through the browser: the invite is minted via the API
// (its dialog flow is covered separately), the invited peer opens the link in
// a fresh tab (cookies are shared across tabs; harmless — enrollment works
// unauthenticated), clicks Show QR code, which must generate the X25519 key,
// PUT the real public key to the backend, and render the QR. The store then
// contains the claimed peer; the invite is consumed.
func TestE2EEnrollment(t *testing.T) {
	browserExecPath(t)
	srv, ctx := deviceIntegrationServer(t)

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256(token)
	if err := ctx.Store.CreatePendingPeer(wireguard.PendingPeer{
		TokenHash: tokenHash, Comment: "BrowserPeer", AllowedIps: prefixes("10.203.0.2/32"), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	link := srv.URL + "/peer/" + base64.RawURLEncoding.EncodeToString(token)

	peerTab := newE2ETab(t, newE2EBrowser(t))
	runWithTimeout(t, "open invite link", peerTab, 45*time.Second,
		chromedp.Navigate(link),
		chromedp.WaitVisible("#ShowQRCodeButton"), // single-use page armed
	)
	// Claim the invite: generateWgConfig runs the whole Web Crypto enrollment.
	runWithTimeout(t, "claim invite", peerTab, 45*time.Second, jsClick("#ShowQRCodeButton"))
	// Success markers: the buttons toggle only after the PUT + QR rendering.
	runWithTimeout(t, "wait enrollment", peerTab, 45*time.Second, chromedp.WaitVisible("#HideQRCodeButton"))
	runWithTimeout(t, "wait QR", peerTab, 10*time.Second, chromedp.WaitVisible("#qrcode"))

	// The store holds the claimed peer; the invite is gone.
	peers, err := ctx.Store.ListPeers()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 || peers[0].Comment != "BrowserPeer" {
		t.Fatalf("enrollment did not reach the store: %+v", peers)
	}
	if remaining, err := ctx.Store.ListPendingPeers(); err != nil || len(remaining) != 0 {
		t.Fatalf("invite not consumed by enrollment: %v / %v", remaining, err)
	}
}

// The browser must support X25519 in Web Crypto — the enrollment flow is
// exactly where this becomes observable; a too-old browser cannot enroll
// peers at all. The probe runs on a real HTTP page: crypto.subtle only
// exists in secure contexts, and about:blank's null origin has none.
func TestE2EWebCryptoX25519Available(t *testing.T) {
	browserExecPath(t)
	srv, _ := newIntegrationServer(t)
	tabCtx := newE2ETab(t, newE2EBrowser(t))
	runWithTimeout(t, "open login page", tabCtx, 15*time.Second, chromedp.Navigate(srv.URL+"/login"))
	actionCtx, cancel := context.WithTimeout(tabCtx, 15*time.Second)
	defer cancel()
	supported, err := chromedp.Run(actionCtx, evalBool(
		`!!window.crypto.subtle && (() => { try { crypto.subtle.generateKey('X25519', false, ['deriveBits']); return true } catch (e) { return false } })()`,
	))
	if err != nil {
		t.Fatal(err)
	}
	if !supported {
		t.Fatal("the installed browser does not support X25519 in Web Crypto; it cannot enroll peers")
	}
}
