package main

import (
	"fmt"
	"log"
	"net/http"
	"net/netip"

	"golang.org/x/crypto/bcrypt"
)

func AuthenticateRequest(request *http.Request, responseWriter http.ResponseWriter, ctx *ServerContext) error {
	// Check IP filter
	hostPort, err := netip.ParseAddrPort(request.RemoteAddr)
	if err != nil {
		http.Error(responseWriter, "Internal Server Error", http.StatusInternalServerError)
		return fmt.Errorf("Request parsing error: %s", err)
	}
	if len(ctx.AdminIpFilter) > 0 {
		ipMatches := false
		for _, subnet := range ctx.AdminIpFilter {
			if subnet.Contains(hostPort.Addr()) {
				ipMatches = true
				break
			}
		}
		if !ipMatches {
			http.Error(responseWriter, "Unauthorized", http.StatusUnauthorized)
			return fmt.Errorf("Request from host %s failed IP filter", hostPort.Addr().String())
		}
	}
	// Check Basic Auth
	username, password, ok := request.BasicAuth()
	if ok {
		if len(username) == 0 && len(password) == 0 {
			log.Printf("From %s: %s %s Logout\n", request.RemoteAddr, request.Method, request.URL.Path)
			// fallthrough
		} else {
			passwordHash, ok := ctx.Config.Admin.Users[username]
			if ok {
				if passwordMatchErr := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); passwordMatchErr == nil {
					return nil
				} else {
					log.Printf("From %s: %s %s HTTP Basic Auth failed, wrong password\n", request.RemoteAddr, request.Method, request.URL.Path)
					// fallthrough
				}
			} else {
				log.Printf("From %s: %s %s HTTP Basic Auth failed, user not found\n", request.RemoteAddr, request.Method, request.URL.Path)
				// fallthrough
			}
		}
	}
	responseWriter.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
	http.Error(responseWriter, "Unauthorized", http.StatusUnauthorized)
	return nil
}
