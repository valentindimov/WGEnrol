package main

import (
	"crypto/tls"
	_ "embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
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

//go:embed index.html
var indexHtmlTemplateString string
var indexHtmlTpl = compileTemplateOrPanic("index.html", indexHtmlTemplateString)

//go:embed enrolment.html
var enrolmentHtmlTemplateString string
var enrolmentHtmlTpl = compileTemplateOrPanic("enrolment.html", enrolmentHtmlTemplateString)

//go:embed login.html
var loginHtmlTemplateString string
var loginHtmlTpl = compileTemplateOrPanic("login.html", loginHtmlTemplateString)

type ServerContext struct {
	stateMutex sync.Mutex
	ConfFile   *WgConf
	Config     *WgEnrolConfig

	AdminIpFilter      []netip.Prefix
	ValidSessionTokens map[string]time.Time // Maps the token to the expiry time
}

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

func wrapHandler(
	handler func(ctx *ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *HandlerError),
	ctx *ServerContext,
	contentType string,
	authenticated bool,
) http.HandlerFunc {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if authenticated {
			if err := AuthenticateRequest(request, responseWriter, ctx); err != nil {
				log.Printf("%s", err.Error())
				return
			}
		}
		ctx.stateMutex.Lock()
		defer ctx.stateMutex.Unlock()
		log.Printf("From %s: %s %s\n", request.RemoteAddr, request.Method, request.URL.Path)
		result, err := handler(ctx, request, responseWriter)
		if err != nil {
			// HTTP error response
			log.Printf("From %s: %s %s - ERROR %s\n", request.RemoteAddr, request.Method, request.URL.Path, err.Error())
			responseWriter.WriteHeader(err.status)
			if err.visible {
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

func getCertificate(_ *tls.ClientHelloInfo, ctx *ServerContext) (*tls.Certificate, error) {
	caFiles, err := tls.LoadX509KeyPair(*ctx.Config.Server.Tls.CertFile, *ctx.Config.Server.Tls.KeyFile)
	if err != nil {
		return nil, err
	}
	return &caFiles, nil
}

func listenAndServe(ctx *ServerContext) {
	// Login/logout
	http.HandleFunc("GET /login", wrapHandler(handleGetLogin, ctx, "text/html", false))
	http.HandleFunc("POST /login", wrapHandler(handlePostLogin, ctx, "text/plain", false))
	http.HandleFunc("POST /logout", wrapHandler(handlePostLogout, ctx, "text/plain", true))
	// Admin panel functions
	http.HandleFunc("GET /", wrapHandler(handleGetRoot, ctx, "text/html", true))
	http.HandleFunc("PUT /peer", wrapHandler(handleEditPeer, ctx, "text/plain", true))
	http.HandleFunc("POST /peer", wrapHandler(handleCreatePeer, ctx, "text/plain", true))
	http.HandleFunc("DELETE /peer/{pubkey}", wrapHandler(handleDeletePeer, ctx, "text/plain", true))
	// Peer enrolment
	http.HandleFunc("GET /peer/{pubkeyPreimage}", wrapHandler(handleGetPeerEnrolmentPage, ctx, "text/html", false))
	http.HandleFunc("PUT /peer/{pubkeyPreimage}", wrapHandler(handleEnrolPeer, ctx, "text/plain", false))

	// Define the server (still uses the DefaultServeMux handler which http.HandleFunc adds to)
	server := http.Server{
		Addr: *ctx.Config.Server.ListenOn,
		TLSConfig: &tls.Config{
			GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) { return getCertificate(info, ctx) },
		},
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
