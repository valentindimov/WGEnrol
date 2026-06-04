package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log"
	"net"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

func AuthenticateRequest(request *http.Request, responseWriter http.ResponseWriter, ctx *ServerContext) error {
	expectedUsernameHash := sha256.Sum256([]byte(*ctx.Config.Admin.Username))
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		http.Error(responseWriter, "Internal Server Error", http.StatusInternalServerError)
		return fmt.Errorf("Request parsing error: %s", err)
	}
	hostIp := net.ParseIP(host)
	if hostIp == nil {
		http.Error(responseWriter, "Internal Server Error", http.StatusInternalServerError)
		return fmt.Errorf("Request parsing error: %s", err)
	}
	if len(ctx.AdminIpFilter) > 0 {
		ipMatches := false
		for _, subnet := range ctx.AdminIpFilter {
			if subnet.Contains(hostIp) {
				ipMatches = true
				break
			}
		}
		if !ipMatches {
			http.Error(responseWriter, "Unauthorized", http.StatusUnauthorized)
			return fmt.Errorf("Request from host %s failed IP filter", host)
		}
	}
	username, password, ok := request.BasicAuth()
	if ok {
		usernameHash := sha256.Sum256([]byte(username))
		usernameMatch := (subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1)
		passwordMatchErr := bcrypt.CompareHashAndPassword([]byte(*ctx.Config.Admin.PasswordHash), []byte(password))
		if usernameMatch && passwordMatchErr == nil {
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
