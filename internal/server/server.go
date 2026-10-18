package server

import (
	"crypto/tls"
	_ "embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"thebasstoon.com/wgenrol/internal/config"
)

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

type HandlerError struct {
	status  int
	message *string
	visible bool
}

func (e *HandlerError) Error() string {
	return fmt.Sprintf("%d %s", e.status, *e.message)
}

func WrapError(err error, status int, visible bool) *HandlerError {
	errMsg := err.Error()
	return &HandlerError{status: status, visible: visible, message: &errMsg}
}

func WrapHandler(
	handler func(ctx *config.ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *HandlerError),
	ctx *config.ServerContext,
	contentType string,
	authenticated bool,
	applyIpFilter bool,
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
		if applyIpFilter {
			if err := ApplyIpFilter(request, responseWriter, ctx); err != nil {
				log.Printf("%s", err.Error())
				return
			}
		}
		if authenticated {
			if err := AuthenticateRequest(request, responseWriter, ctx); err != nil {
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

type CertCache struct {
	lock            sync.Mutex
	cert            *tls.Certificate
	certMod, keyMod *time.Time
}

func GetCertificate(_ *tls.ClientHelloInfo, ctx *config.ServerContext, cache *CertCache) (*tls.Certificate, error) {
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

func ListenAndServe(ctx *config.ServerContext) {
	// Login/logout
	http.HandleFunc("GET /login", WrapHandler(handleGetLogin, ctx, "text/html", false, true, nil, false))
	http.HandleFunc("POST /login", WrapHandler(handlePostLogin, ctx, "text/plain", false, true, nil, false))
	http.HandleFunc("POST /logout", WrapHandler(handlePostLogout, ctx, "text/plain", true, true, nil, false))
	// Admin panel functions
	http.HandleFunc("GET /", WrapHandler(handleGetRoot, ctx, "text/html", true, true, nil, false))
	http.HandleFunc("PUT /peer", WrapHandler(handleEditPeer, ctx, "text/plain", true, true, nil, false))
	http.HandleFunc("POST /peer", WrapHandler(handleCreatePeer, ctx, "text/plain", true, true, nil, false))
	http.HandleFunc("DELETE /peer/{pubkey}", WrapHandler(handleDeletePeer, ctx, "text/plain", true, true, nil, false))
	// Peer enrolment
	pubkeyPreimageMask := "/peer/{pubkeyPreimage}"
	http.HandleFunc("GET /peer/{pubkeyPreimage}", WrapHandler(handleGetPeerEnrolmentPage, ctx, "text/html", false, false, &pubkeyPreimageMask, true))
	http.HandleFunc("PUT /peer/{pubkeyPreimage}", WrapHandler(handleEnrolPeer, ctx, "text/plain", false, false, &pubkeyPreimageMask, true))

	// Define the server (still uses the DefaultServeMux handler which http.HandleFunc adds to)
	var certCache CertCache
	server := http.Server{
		Addr: *ctx.Config.Server.ListenOn,
		TLSConfig: &tls.Config{
			GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return GetCertificate(info, ctx, &certCache)
			},
			MinVersion: tls.VersionTLS12,
		},
		// Timeouts - prevent slowloris-style attack
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       5 * time.Second,
	}

	var err error
	if ctx.Config.Server.Tls.Enabled {
		err = server.ListenAndServeTLS("", "")
	} else {
		err = server.ListenAndServe()
	}
	if err != nil {
		log.Fatal(err)
	}
}
