package server

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"thebasstoon.com/wgenrol/internal/config"
)

func GetSessionToken(request *http.Request) (*string, error) {
	sessionCookie, err := request.Cookie("session")
	if err != nil {
		return nil, err
	}
	cookieContents, err := base64.URLEncoding.DecodeString(sessionCookie.Value)
	if err != nil {
		return nil, err
	}
	token := string(cookieContents)
	return &token, nil
}

func ApplyIpFilter(request *http.Request, responseWriter http.ResponseWriter, ctx *config.ServerContext) error {
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
	return nil
}

func AuthenticateRequest(request *http.Request, responseWriter http.ResponseWriter, ctx *config.ServerContext) error {
	// Check session cookie
	token, err := GetSessionToken(request)
	if err != nil {
		http.Redirect(responseWriter, request, "/login", http.StatusFound)
		return fmt.Errorf("Request from host %s missing/malformed session cookie (%s)", request.RemoteAddr, err.Error())
	}
	validity, ok := ctx.ValidSessionTokens[*token]
	if ok && (validity.Compare(time.Now()) == 1) {
		// Validity is extended to 1 hour after the last activity
		ctx.ValidSessionTokens[*token] = time.Now().Add(time.Hour)
		return nil
	} else {
		http.Redirect(responseWriter, request, "/login", http.StatusFound)
		return fmt.Errorf("Request from host %s invalid session cookie", request.RemoteAddr)
	}
}
