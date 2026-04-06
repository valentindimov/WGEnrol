package main

import (
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"sync"
	"text/template"
)

//go:embed index.html.tpl
var indexHtmlTemplate string

func getRoot(tmpl *template.Template, stateMutex *sync.Mutex, numRequests *int) http.HandlerFunc {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		stateMutex.Lock()
		defer stateMutex.Unlock()
		*numRequests++

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
