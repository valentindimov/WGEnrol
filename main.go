package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"sync"
)

var stateMutex sync.Mutex
var numRequests = 0

var expectedUsername = "admin"
var expectedPassword = "password"

func getRoot(responseWriter http.ResponseWriter, request *http.Request) {
	stateMutex.Lock()
	defer stateMutex.Unlock()
	numRequests++

	fmt.Printf("got / request\n")
	fmt.Fprintf(responseWriter, "Number of requests: %d\n", numRequests)
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
			}
		}
		responseWriter.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(responseWriter, "Unauthorized", http.StatusUnauthorized)
	})
}

func main() {
	http.HandleFunc("/", basicAuth(getRoot))

	http.ListenAndServe("localhost:1234", nil)
}
