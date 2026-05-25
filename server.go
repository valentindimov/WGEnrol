package main

import (
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
)

func compileTemplateOrPanic(name string, source string) *template.Template {
	result, err := template.New(name).Parse(source)
	if err != nil {
		panic(err)
	}
	return result
}

//go:embed index.html
var indexHtmlTemplateString string
var indexHtmlTpl = compileTemplateOrPanic("index.html", indexHtmlTemplateString)

//go:embed enrolment.html
var enrolmentHtmlTemplateString string
var enrolmentHtmlTpl = compileTemplateOrPanic("enrolment.html", enrolmentHtmlTemplateString)

type ServerContext struct {
	stateMutex sync.Mutex
	confFile   *WgConf
	config     *WgEnrolConfig
}

func adminFuncWrapper(next http.HandlerFunc, ctx *ServerContext) http.HandlerFunc {
	expectedUsernameHash := sha256.Sum256([]byte(*ctx.config.Admin.Username))
	expectedPasswordHash, err := hex.DecodeString(*ctx.config.Admin.PasswordHash)
	if err != nil {
		log.Fatal(err)
	}
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		host, _, err := net.SplitHostPort(request.RemoteAddr)
		if err != nil {
			log.Printf("Request parsing error: %s", err)
			http.Error(responseWriter, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if len(ctx.config.Admin.IPFilter) > 0 && !slices.Contains(ctx.config.Admin.IPFilter, host) {
			log.Printf("Request from host %s failed IP filter", host)
			http.Error(responseWriter, "Unauthorized", http.StatusUnauthorized)
			return
		}
		username, password, ok := request.BasicAuth()
		if ok {
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			usernameMatch := (subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1)
			passwordMatch := (subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1)
			if usernameMatch && passwordMatch {
				next.ServeHTTP(responseWriter, request)
				return
			} else if len(username) == 0 && len(password) == 0 {
				log.Printf("From %s: %s %s Logout\n", request.RemoteAddr, request.Method, request.URL.Path)
			} else {
				log.Printf("From %s: %s %s HTTP Basic Auth failed\n", request.RemoteAddr, request.Method, request.URL.Path)
			}
		}
		responseWriter.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(responseWriter, "Unauthorized", http.StatusUnauthorized)
	})
}

func sendHttpError(w http.ResponseWriter, err error, statusCode int, reportError bool) {
	log.Print(err)
	var errorMessage string
	if reportError {
		errorMessage = fmt.Sprintf("%s", err)
	} else {
		errorMessage = "Error"
	}
	http.Error(w, errorMessage, statusCode)
}

func wrapFuncAsHandler(next func(ctx *ServerContext, w http.ResponseWriter, r *http.Request), ctx *ServerContext) http.HandlerFunc {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		ctx.stateMutex.Lock()
		defer ctx.stateMutex.Unlock()
		log.Printf("From %s: %s %s\n", request.RemoteAddr, request.Method, request.URL.Path)
		next(ctx, responseWriter, request)
	})
}

// GET /
func handleGetRoot(ctx *ServerContext, responseWriter http.ResponseWriter, request *http.Request) {
	responseWriter.Header().Set("Content-Type", "text/html")
	var sortedPeersList []WgPeer
	for _, peer := range ctx.confFile.Peers {
		sortedPeersList = append(sortedPeersList, peer)
	}
	sort.Slice(sortedPeersList, func(i, j int) bool { return sortedPeersList[i].Comment < sortedPeersList[j].Comment })
	err := indexHtmlTpl.Execute(responseWriter, map[string]any{
		"peers": sortedPeersList,
	})
	if err != nil {
		log.Printf("Templating error: %s", err)
	}
}

// PUT /peer
func handleEditPeer(ctx *ServerContext, responseWriter http.ResponseWriter, request *http.Request) {
	requestBytes, err := io.ReadAll(request.Body)
	if err != nil {
		sendHttpError(responseWriter, err, 400, false)
		return
	}
	var requestPeerObj WgPeer
	err = json.Unmarshal(requestBytes, &requestPeerObj)
	if err != nil {
		sendHttpError(responseWriter, err, 400, true)
		return
	}
	err = requestPeerObj.validate()
	if err != nil {
		sendHttpError(responseWriter, err, 400, true)
		return
	}

	if _, ok := ctx.confFile.Peers[requestPeerObj.Pubkey]; ok {
		ctx.confFile.Peers[requestPeerObj.Pubkey] = requestPeerObj
	} else {
		sendHttpError(responseWriter, err, 404, true)
		return
	}
	err = ctx.confFile.save(ctx.config.Wireguard.ifname)
	if err != nil {
		sendHttpError(responseWriter, err, 500, false)
		return
	}

	responseWriter.WriteHeader(http.StatusOK)
}

// POST /peer
func handleCreatePeer(ctx *ServerContext, responseWriter http.ResponseWriter, request *http.Request) {
	requestBytes, err := io.ReadAll(request.Body)
	if err != nil {
		sendHttpError(responseWriter, err, 400, false)
		return
	}
	var requestPeerObj WgPeer
	err = json.Unmarshal(requestBytes, &requestPeerObj)
	if err != nil {
		sendHttpError(responseWriter, err, 400, true)
		return
	}
	err = requestPeerObj.validate()
	if err != nil {
		sendHttpError(responseWriter, err, 400, true)
		return
	}

	if _, ok := ctx.confFile.Peers[requestPeerObj.Pubkey]; ok {
		sendHttpError(responseWriter, fmt.Errorf("Peer already exists"), 400, true)
		return
	} else {
		ctx.confFile.Peers[requestPeerObj.Pubkey] = requestPeerObj
	}
	err = ctx.confFile.save(ctx.config.Wireguard.ifname)
	if err != nil {
		sendHttpError(responseWriter, err, 500, true)
		return
	}

	responseWriter.WriteHeader(http.StatusOK)
}

// DELETE /peer/{pubkey}
// pubkey must be encoded as URL-safe base64 (and not the standard Base64 WireGuard keys are usually encoded as)
func handleDeletePeer(ctx *ServerContext, responseWriter http.ResponseWriter, request *http.Request) {
	pubkeyBase64Url := request.PathValue("pubkey")
	pubkeyDecoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(pubkeyBase64Url)
	if err != nil {
		sendHttpError(responseWriter, err, 400, true)
		return
	}
	pubkey := base64.StdEncoding.EncodeToString(pubkeyDecoded)

	delete(ctx.confFile.Peers, pubkey)
	err = ctx.confFile.save(ctx.config.Wireguard.ifname)
	if err != nil {
		sendHttpError(responseWriter, err, 500, false)
		return
	}

	responseWriter.WriteHeader(http.StatusOK)
}

func getFirstIPInNetwork(network *net.IPNet) net.IP {
	ones, bits := network.Mask.Size()
	if ones == bits {
		return network.IP
	} else {
		networkIPMasked := make([]byte, len(network.IP))
		for i := 0; i < len(networkIPMasked); i++ {
			networkIPMasked[i] = network.IP[i] & network.Mask[i]
		}
		networkIPMasked[len(networkIPMasked)-1] |= 1
		return networkIPMasked
	}
}

func computePeerIPs(peerAllowedIps string, cfg *WgConf) (*string, error) {
	ips := make([]net.IP, 0)
	if len(strings.Trim(peerAllowedIps, " ")) > 0 {
		addrs := strings.SplitSeq(peerAllowedIps, ",")
		for addr := range addrs {
			_, network, err := net.ParseCIDR(strings.Trim(addr, " "))
			if err != nil {
				return nil, err
			}
			ips = append(ips, getFirstIPInNetwork(network))
		}
	}
	peerNetworks := make([]string, 0)
	for _, ip := range ips {
		for _, network := range cfg.VpnNetworks {
			if network.Contains(ip) {
				ipWithNet := net.IPNet{
					IP:   ip,
					Mask: network.Mask,
				}
				peerNetworks = append(peerNetworks, ipWithNet.String())
			}
		}
	}
	result := strings.Join(peerNetworks, ",")
	return &result, nil
}

// GET /peer/{pubkeyPreimage}
func handleGetPeerEnrolmentPage(ctx *ServerContext, responseWriter http.ResponseWriter, request *http.Request) {
	pubkeyPreimageBase64Url := request.PathValue("pubkeyPreimage")
	pubkeyPreimageDecoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(pubkeyPreimageBase64Url)
	if err != nil {
		sendHttpError(responseWriter, err, 400, true)
		return
	}
	pubkeyBytes := sha256.Sum256([]byte(pubkeyPreimageDecoded))
	pubkey := base64.StdEncoding.EncodeToString(pubkeyBytes[:])

	if peer, ok := ctx.confFile.Peers[pubkey]; ok {
		peerAddrs, err := computePeerIPs(peer.AllowedIps, ctx.confFile)
		if err != nil {
			sendHttpError(responseWriter, err, 500, false)
			return
		}
		responseWriter.Header().Set("Content-Type", "text/html")
		err = enrolmentHtmlTpl.Execute(responseWriter, map[string]any{
			"peerAddresses":      peerAddrs,
			"pubkeyPreimage":     pubkeyPreimageBase64Url,
			"advertisedDNS":      strings.Join(ctx.config.Advertise.Dns, ","),
			"serverPublicKey":    ctx.config.Advertise.PublicKey,
			"advertisedNetworks": strings.Join(ctx.config.Advertise.Subnets, ","),
			"advertisedEndpoint": ctx.config.Advertise.Endpoint,
		})
		if err != nil {
			log.Printf("Templating error: %s", err)
		}
	} else {
		sendHttpError(responseWriter, fmt.Errorf("Not Found"), 404, false)
		return
	}
}

// PUT /peer/{pubkeyPreimage}
func handleEnrolPeer(ctx *ServerContext, responseWriter http.ResponseWriter, request *http.Request) {
	type SetPeerPubkeyRequest struct {
		NewPubKey string
		NewPSK    *string
	}

	pubkeyPreimageBase64Url := request.PathValue("pubkeyPreimage")
	pubkeyPreimageDecoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(pubkeyPreimageBase64Url)
	if err != nil {
		sendHttpError(responseWriter, err, 400, false)
		return
	}
	pubkeyBytes := sha256.Sum256([]byte(pubkeyPreimageDecoded))
	pubkey := base64.StdEncoding.EncodeToString(pubkeyBytes[:])

	// The logic behind peer enrolment is as follows:
	// - The client must provide a SHA256 preimage of the peer's public key.
	// - This proves that the PublicKey field is not a real public key, but a "pending" peer
	// - Thus possession of the key preimage allows you to change the pubkey (and only the pubkey)

	if peerObj, ok := ctx.confFile.Peers[pubkey]; ok {
		requestBytes, err := io.ReadAll(request.Body)
		if err != nil {
			sendHttpError(responseWriter, err, 400, false)
			return
		}
		var requestObj SetPeerPubkeyRequest
		err = json.Unmarshal(requestBytes, &requestObj)
		if err != nil {
			sendHttpError(responseWriter, err, 400, true)
			return
		}
		err = validateWireguardKey(requestObj.NewPubKey)
		if err != nil {
			sendHttpError(responseWriter, err, 400, true)
			return
		}
		if requestObj.NewPSK != nil {
			err = validateWireguardKey(requestObj.NewPubKey)
			if err != nil {
				sendHttpError(responseWriter, err, 400, true)
				return
			}
		}
		delete(ctx.confFile.Peers, pubkey)
		peerObj.Pubkey = requestObj.NewPubKey
		peerObj.PresharedKey = requestObj.NewPSK
		ctx.confFile.Peers[requestObj.NewPubKey] = peerObj
		err = ctx.confFile.save(ctx.config.Wireguard.ifname)
		if err != nil {
			sendHttpError(responseWriter, err, 500, false)
			return
		}
	} else {
		sendHttpError(responseWriter, fmt.Errorf("Not Found"), 404, true)
		return
	}

	responseWriter.WriteHeader(http.StatusOK)
}

func listenAndServe(ctx *ServerContext) {
	// Admin panel functions
	http.HandleFunc("GET /", adminFuncWrapper(wrapFuncAsHandler(handleGetRoot, ctx), ctx))
	http.HandleFunc("PUT /peer", adminFuncWrapper(wrapFuncAsHandler(handleEditPeer, ctx), ctx))
	http.HandleFunc("POST /peer", adminFuncWrapper(wrapFuncAsHandler(handleCreatePeer, ctx), ctx))
	http.HandleFunc("DELETE /peer/{pubkey}", adminFuncWrapper(wrapFuncAsHandler(handleDeletePeer, ctx), ctx))
	// Peer enrolment
	http.HandleFunc("GET /peer/{pubkeyPreimage}", wrapFuncAsHandler(handleGetPeerEnrolmentPage, ctx))
	http.HandleFunc("PUT /peer/{pubkeyPreimage}", wrapFuncAsHandler(handleEnrolPeer, ctx))

	var err error
	if ctx.config.Server.Tls.CertFile != nil && ctx.config.Server.Tls.KeyFile != nil {
		err = http.ListenAndServeTLS(*ctx.config.Server.ListenOn, *ctx.config.Server.Tls.CertFile, *ctx.config.Server.Tls.KeyFile, nil)
	} else {
		err = http.ListenAndServe(*ctx.config.Server.ListenOn, nil)
	}
	if err != nil {
		log.Fatal(err)
	}
}
