package main

import (
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sync"
	"text/template"
)

//go:embed index.html.tpl
var indexHtmlTemplate string

var stateMutex sync.Mutex
var numRequests = 0

var expectedUsername = "admin"
var expectedPassword = "password"

func getRoot(responseWriter http.ResponseWriter, request *http.Request) {
	stateMutex.Lock()
	defer stateMutex.Unlock()
	numRequests++

	log.Printf("From %s: %s %s\n", request.RemoteAddr, request.Method, request.URL.Path)

	tmpl, err := template.New("index.html").Parse(indexHtmlTemplate)
	if err != nil {
		log.Fatal(err)
	}
	err = tmpl.Execute(responseWriter, map[string]string{
		"numRequests": fmt.Sprintf("%d", numRequests),
	})
	if err != nil {
		log.Fatal(err)
	}
}

func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		username, password, ok := request.BasicAuth()
		if ok {
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			expectedUsernameHash := sha256.Sum256([]byte(expectedUsername))
			expectedPasswordHash := sha256.Sum256([]byte(expectedPassword))
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

func main() {
	listenOnPtr := flag.String("listen", ":8080", "Address and port to bind on")
	ifnamePtr := flag.String("ifname", "wg0", "WireGuard interface to manage. Creates it if it's missing.")
	flag.Parse()

	log.Printf("Managing interface %s\n", *ifnamePtr)
	log.Printf("Listening on %s\n", *listenOnPtr)
	http.HandleFunc("GET /", basicAuth(getRoot))
	http.ListenAndServe(*listenOnPtr, nil)
}
