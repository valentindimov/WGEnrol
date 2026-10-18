package server

import (
	"crypto/tls"
	_ "embed"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"

	"thebasstoon.com/wgenrol/internal/config"
	"thebasstoon.com/wgenrol/internal/storage"
)

// ServerContext joins everything the HTTP layer needs at runtime: the parsed
// configuration, the peer store, per-connection admin state, and the mail
// hook (which doubles as a test seam). Constructed by the entry point via
// NewContext, then treated as immutable except for the mutex-guarded state.
type ServerContext struct {
	StateMutex sync.Mutex
	Store      storage.PeerStore
	Config     *config.WgEnrolConfig

	AdminIpFilter []netip.Prefix
	// Sessions persists admin login sessions in the peer database, so they
	// survive restarts. All session access runs under StateMutex via
	// wrapHandler.
	Sessions storage.SessionStore

	// SendMailFn mirrors the signature of net/smtp.SendMail; nil in
	// production. Part of the same test seam as the device hooks: invite
	// emails can be captured without talking to a real relay.
	SendMailFn func(addr string, auth smtp.Auth, from string, to []string, msg []byte) error
}

// NewContext assembles the server runtime context from the parsed
// configuration and the peer/session stores opened by the entry point.
func NewContext(cfg *config.WgEnrolConfig, store storage.PeerStore, sessions storage.SessionStore) (*ServerContext, error) {
	ipFilter, err := config.ParseIPNetList(cfg.Admin.IPFilter)
	if err != nil {
		return nil, err
	}
	return &ServerContext{
		Store:  store,
		Config: cfg,

		AdminIpFilter: ipFilter,
		Sessions:      sessions,
	}, nil
}

func compileTemplateOrPanic(name string, source string) *template.Template {
	result, err := template.New(name).Funcs(template.FuncMap{
		"subnetListToString": func(netList []netip.Prefix) string {
			peerIpsStrList := make([]string, 0, len(netList))
			for _, prefix := range netList {
				peerIpsStrList = append(peerIpsStrList, prefix.String())
			}
			return strings.Join(peerIpsStrList, ",")
		},
	}).Parse(source)
	if err != nil {
		panic(err)
	}
	return result
}

//go:embed templates/index.html
var indexHtmlTemplateString string
var indexHtmlTpl = compileTemplateOrPanic("index.html", indexHtmlTemplateString)

//go:embed templates/enrolment.html
var enrolmentHtmlTemplateString string
var enrolmentHtmlTpl = compileTemplateOrPanic("enrolment.html", enrolmentHtmlTemplateString)

//go:embed templates/login.html
var loginHtmlTemplateString string
var loginHtmlTpl = compileTemplateOrPanic("login.html", loginHtmlTemplateString)

type handlerError struct {
	status  int
	message *string
	visible bool
}

func (e *handlerError) Error() string {
	return fmt.Sprintf("%d %s", e.status, *e.message)
}

func wrapError(err error, status int, visible bool) *handlerError {
	errMsg := err.Error()
	return &handlerError{status: status, visible: visible, message: &errMsg}
}

func wrapHandler(
	handler func(ctx *ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *handlerError),
	ctx *ServerContext,
	contentType string,
	authenticated bool,
	doApplyIpFilter bool,
	pathMask *string,
	maskErrors bool,
) http.HandlerFunc {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		ctx.StateMutex.Lock()
		defer ctx.StateMutex.Unlock()
		// Set security headers
		responseWriter.Header().Set("X-Content-Type-Options", "nosniff")
		if ctx.Config.Server.Tls.Enabled {
			responseWriter.Header().Set("Strict-Transport-Security", "max-age=2592000; includeSubDomains")
		}
		// Apply filters / auth
		if doApplyIpFilter {
			if err := applyIpFilter(request, responseWriter, ctx); err != nil {
				log.Printf("%s", err.Error())
				return
			}
		}
		if authenticated {
			if err := authenticateRequest(request, responseWriter, ctx); err != nil {
				log.Printf("%s", err.Error())
				return
			}
		}
		var pathToLog string
		if pathMask == nil {
			pathToLog = request.URL.Path
		} else {
			pathToLog = *pathMask
		}
		log.Printf("From %s: %s %s\n", request.RemoteAddr, request.Method, pathToLog)
		// Safety measure: the body is always limited to 1 MB. Payloads are tiny JSON so this is way bigger than we need anyway.
		request.Body = http.MaxBytesReader(responseWriter, request.Body, 1024*1024)
		// Run the handler
		result, err := handler(ctx, request, responseWriter)
		if err != nil {
			// HTTP error response
			log.Printf("From %s: %s %s - ERROR %s\n", request.RemoteAddr, request.Method, pathToLog, err.Error())
			responseWriter.WriteHeader(err.status)
			if err.visible && !maskErrors { // error messages are only displayed on authenticated endpoints (login errors are displayed too, though)
				responseWriter.Write([]byte(*err.message))
			}
		} else if result != nil {
			// HTTP success response with a body
			responseWriter.Header().Set("Content-Type", contentType)
			responseWriter.Write(result)
		} else {
			// HTTP success response with no body
			responseWriter.WriteHeader(http.StatusOK)
		}
	})
}

type certCache struct {
	lock            sync.Mutex
	cert            *tls.Certificate
	certMod, keyMod *time.Time
}

func getCertificate(_ *tls.ClientHelloInfo, ctx *ServerContext, cache *certCache) (*tls.Certificate, error) {
	if cache == nil {
		log.Fatal("CertCache is missing but TLS is enabled.") // This should never happen, but just in case..
	}
	certStat, err := os.Stat(*ctx.Config.Server.Tls.CertFile)
	if err != nil {
		return nil, fmt.Errorf("Failed to stat certfile: %s", err.Error())
	}
	keyStat, err := os.Stat(*ctx.Config.Server.Tls.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("Failed to stat keyfile: %s", err.Error())
	}

	cache.lock.Lock()
	defer cache.lock.Unlock()

	if cache.cert == nil ||
		cache.certMod == nil ||
		cache.keyMod == nil ||
		cache.certMod.Compare(certStat.ModTime()) != 0 ||
		cache.keyMod.Compare(keyStat.ModTime()) != 0 {
		certificate, err := tls.LoadX509KeyPair(*ctx.Config.Server.Tls.CertFile, *ctx.Config.Server.Tls.KeyFile)
		if err != nil {
			if cache.cert != nil {
				log.Printf("Warning: certificate files were renewed but don't match. Using last-known good certificate.")
				return cache.cert, nil
			} else {
				return nil, err
			}
		}
		cache.cert = &certificate
		certModTime := certStat.ModTime()
		cache.certMod = &certModTime
		keyModTime := keyStat.ModTime()
		cache.keyMod = &keyModTime
	}

	return cache.cert, nil
}

// newServeMux registers all routes on a fresh ServeMux and returns it. It is
// separate from ListenAndServe so tests can serve real HTTP requests through
// the exact production route table via httptest.
func newServeMux(ctx *ServerContext) *http.ServeMux {
	mux := http.NewServeMux()
	// Login/logout
	mux.HandleFunc("GET /login", wrapHandler(handleGetLogin, ctx, "text/html", false, true, nil, false))
	mux.HandleFunc("POST /login", wrapHandler(handlePostLogin, ctx, "text/plain", false, true, nil, false))
	mux.HandleFunc("POST /logout", wrapHandler(handlePostLogout, ctx, "text/plain", true, true, nil, false))
	// Admin panel functions
	mux.HandleFunc("GET /", wrapHandler(handleGetRoot, ctx, "text/html", true, true, nil, false))
	mux.HandleFunc("PUT /peer", wrapHandler(handleEditPeer, ctx, "text/plain", true, true, nil, false))
	mux.HandleFunc("DELETE /peer/{pubkey}", wrapHandler(handleDeletePeer, ctx, "text/plain", true, true, nil, false))
	// Pending enrollments (invite management)
	mux.HandleFunc("POST /pending", wrapHandler(handleCreatePending, ctx, "text/plain", true, true, nil, false))
	mux.HandleFunc("PUT /pending/{tokenHash}", wrapHandler(handleEditPending, ctx, "text/plain", true, true, nil, false))
	mux.HandleFunc("DELETE /pending/{tokenHash}", wrapHandler(handleDeletePending, ctx, "text/plain", true, true, nil, false))
	// Peer enrolment
	tokenPathMask := "/peer/{token}"
	mux.HandleFunc("GET /peer/{token}", wrapHandler(handleGetPeerEnrolmentPage, ctx, "text/html", false, false, &tokenPathMask, true))
	mux.HandleFunc("PUT /peer/{token}", wrapHandler(handleEnrolPeer, ctx, "text/plain", false, false, &tokenPathMask, true))
	return mux
}

// ListenAndServe builds the server (routes, TLS, timeouts) and blocks until
// it stops. Its error is returned rather than fatal-ed, so callers decide how
// to surface it.
// ListenAndServe binds the configured address and serves until it stops,
// returning the resulting error (callers decide how to surface it).
func ListenAndServe(ctx *ServerContext) error {
	ln, err := net.Listen("tcp", *ctx.Config.Server.ListenOn)
	if err != nil {
		return err
	}
	return serve(ctx, ln)
}

// serve runs the HTTP(S) server on an existing listener. It is separate from
// ListenAndServe so tests can attach their own (ephemeral) listeners,
// including a real TLS listener.
func serve(ctx *ServerContext, ln net.Listener) error {
	mux := newServeMux(ctx)

	var certCache certCache
	srv := http.Server{
		Addr:    ln.Addr().String(),
		Handler: mux,
		TLSConfig: &tls.Config{
			GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return getCertificate(info, ctx, &certCache)
			},
			MinVersion: tls.VersionTLS12,
		},
		// Timeouts - prevent slowloris-style attack
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       5 * time.Second,
	}

	if ctx.Config.Server.Tls.Enabled {
		return srv.ServeTLS(ln, "", "")
	}
	return srv.Serve(ln)
}
