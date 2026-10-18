package server

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/netip"
	"time"
)

func getSessionToken(request *http.Request) (*string, error) {
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

func applyIpFilter(request *http.Request, responseWriter http.ResponseWriter, ctx *ServerContext) error {
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

func authenticateRequest(request *http.Request, responseWriter http.ResponseWriter, ctx *ServerContext) error {
	// Check session cookie
	token, err := getSessionToken(request)
	if err != nil {
		http.Redirect(responseWriter, request, "/login", http.StatusFound)
		return fmt.Errorf("Request from host %s missing/malformed session cookie (%s)", request.RemoteAddr, err.Error())
	}
	// TouchSession atomically authenticates the token and slides its expiry.
	// A database failure here is a hard 500, not a redirect: a failing store
	// must neither lock every admin out nor silently bypass the check.
	valid, err := ctx.Sessions.TouchSession(*token, time.Now().Add(time.Hour))
	if err != nil {
		http.Error(responseWriter, "Internal Server Error", http.StatusInternalServerError)
		return fmt.Errorf("Request from host %s: session store failure: %s", request.RemoteAddr, err.Error())
	}
	if !valid {
		http.Redirect(responseWriter, request, "/login", http.StatusFound)
		return fmt.Errorf("Request from host %s invalid session cookie", request.RemoteAddr)
	}
	return nil
}
