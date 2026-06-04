package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"slices"
)

func AuthenticateRequest(request *http.Request, responseWriter http.ResponseWriter, ctx *ServerContext) error {
	expectedUsernameHash := sha256.Sum256([]byte(*ctx.config.Admin.Username))
	expectedPasswordHash, err := hex.DecodeString(*ctx.config.Admin.PasswordHash)
	if err != nil {
		log.Fatal(err)
	}
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		http.Error(responseWriter, "Internal Server Error", http.StatusInternalServerError)
		return fmt.Errorf("Request parsing error: %s", err)
	}
	if len(ctx.config.Admin.IPFilter) > 0 && !slices.Contains(ctx.config.Admin.IPFilter, host) {
		http.Error(responseWriter, "Unauthorized", http.StatusUnauthorized)
		return fmt.Errorf("Request from host %s failed IP filter", host)
	}
	username, password, ok := request.BasicAuth()
	if ok {
		usernameHash := sha256.Sum256([]byte(username))
		passwordHash := sha256.Sum256([]byte(password))
		usernameMatch := (subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1)
		passwordMatch := (subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1)
		if usernameMatch && passwordMatch {
			return nil
		} else if len(username) == 0 && len(password) == 0 {
			log.Printf("From %s: %s %s Logout\n", request.RemoteAddr, request.Method, request.URL.Path)
			// fallthrough
		} else {
			log.Printf("From %s: %s %s HTTP Basic Auth failed\n", request.RemoteAddr, request.Method, request.URL.Path)
			// fallthrough
		}
	}
	responseWriter.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
	http.Error(responseWriter, "Unauthorized", http.StatusUnauthorized)
	return nil
}
