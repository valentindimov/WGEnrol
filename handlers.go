package main

import (
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"text/template"
)

//go:embed index.html.tpl
var indexHtmlTemplate string

type ServerContext struct {
	stateMutex   *sync.Mutex
	ifname       string
	indexHtmlTpl *template.Template
}

func basicAuthWrapper(next http.HandlerFunc, expectedUsername string, expectedPasswordSha256 string) http.HandlerFunc {
	expectedUsernameHash := sha256.Sum256([]byte(expectedUsername))
	expectedPasswordHash, err := hex.DecodeString(expectedPasswordSha256)
	if err != nil {
		log.Fatal(err)
	}
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		username, password, ok := request.BasicAuth()
		if ok {
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			usernameMatch := (subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1)
			passwordMatch := (subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1)
			if usernameMatch && passwordMatch {
				next.ServeHTTP(responseWriter, request)
				return
			} else {
				log.Printf("From %s: %s %s HTTP Basic Auth failed\n", request.RemoteAddr, request.Method, request.URL.Path)
			}
		}
		responseWriter.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(responseWriter, "Unauthorized", http.StatusUnauthorized)
	})
}

func wrapFuncAsHandler(next func(ctx *ServerContext, w http.ResponseWriter, r *http.Request) error, ctx *ServerContext) http.HandlerFunc {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		ctx.stateMutex.Lock()
		defer ctx.stateMutex.Unlock()
		log.Printf("From %s: %s %s\n", request.RemoteAddr, request.Method, request.URL.Path)
		err := next(ctx, responseWriter, request)
		if err != nil {
			http.Error(responseWriter, "Internal Server Error", http.StatusInternalServerError)
			log.Print(err)
		}
	})
}

// GET /
func handleGetRoot(ctx *ServerContext, responseWriter http.ResponseWriter, request *http.Request) error {
	responseWriter.Header().Set("Content-Type", "text/html")
	return ctx.indexHtmlTpl.Execute(responseWriter, map[string]string{})
}

// GET /peers
func handleGetPeers(ctx *ServerContext, responseWriter http.ResponseWriter, request *http.Request) error {
	wgConf, err := loadWgConf(ctx.ifname)
	if err != nil {
		return err
	}
	peersMap, err := getPeers(wgConf)
	if err != nil {
		return err
	}
	peersMapAsJson, err := json.Marshal(peersMap)
	if err != nil {
		return err
	}
	responseWriter.Header().Set("Content-Type", "application/json")
	responseWriter.Write(peersMapAsJson)
	return nil
}

// PUT /peers
func handlePutPeers(ctx *ServerContext, responseWriter http.ResponseWriter, request *http.Request) error {
	// TODO
	return nil
}

// DELETE /peers/{pubkey}
func handleDeletePeers(ctx *ServerContext, responseWriter http.ResponseWriter, request *http.Request) error {
	// TODO
	return nil
}

// POST /enrolments
func handleCreateEnrolment(ctx *ServerContext, responseWriter http.ResponseWriter, request *http.Request) error {
	// TODO
	return nil
}

// GET /enrolments/{key}
func handleGetEnrolmentPage(ctx *ServerContext, responseWriter http.ResponseWriter, request *http.Request) error {
	// TODO
	return nil
}

// POST /enrolments/{key}
func handleEnrolNewPeer(ctx *ServerContext, responseWriter http.ResponseWriter, request *http.Request) error {
	// TODO
	return nil
}

func listenAndServe(listenOnPtr *string, ifname string, adminUser string, adminPasswordHash string) {
	indexHtmlTpl, err := template.New("index.html").Parse(indexHtmlTemplate)
	if err != nil {
		log.Fatal(err)
	}
	ctx := ServerContext{
		ifname:       ifname,
		indexHtmlTpl: indexHtmlTpl,
	}

	http.HandleFunc("GET /", basicAuthWrapper(wrapFuncAsHandler(handleGetRoot, &ctx), adminUser, adminPasswordHash))
	http.HandleFunc("GET /peers", basicAuthWrapper(wrapFuncAsHandler(handleGetPeers, &ctx), adminUser, adminPasswordHash))
	http.ListenAndServe(*listenOnPtr, nil)
}
