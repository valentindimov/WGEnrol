package main

import (
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"text/template"
)

//go:embed index.html.tpl
var indexHtmlTemplate string

var stateMutex sync.Mutex
var numRequests = 0

func getRoot(tmpl *template.Template) http.HandlerFunc {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		stateMutex.Lock()
		defer stateMutex.Unlock()
		numRequests++

		log.Printf("From %s: %s %s\n", request.RemoteAddr, request.Method, request.URL.Path)

		tmplErr := tmpl.Execute(responseWriter, map[string]string{
			"numRequests": fmt.Sprintf("%d", numRequests),
		})
		if tmplErr != nil {
			http.Error(responseWriter, "Internal Server Error", http.StatusInternalServerError)
			log.Print(tmplErr)
		}
	})
}

func basicAuthWrapper(next http.HandlerFunc, expectedUsername string, expectedPassword string) http.HandlerFunc {
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

	adminUser, adminUserFound := os.LookupEnv("ADMIN_USER")
	if !adminUserFound {
		log.Fatal("ADMIN_USER environment variable is required.")
	}
	adminPassword, adminPasswordFound := os.LookupEnv("ADMIN_PASSWORD")
	if !adminPasswordFound {
		log.Fatal("ADMIN_PASSWORD environment variable is required.")
	}

	tmpl, err := template.New("index.html").Parse(indexHtmlTemplate)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Managing interface %s\n", *ifnamePtr)
	log.Printf("Listening on %s\n", *listenOnPtr)
	http.HandleFunc("GET /", basicAuthWrapper(getRoot(tmpl), adminUser, adminPassword))
	http.ListenAndServe(*listenOnPtr, nil)
}
