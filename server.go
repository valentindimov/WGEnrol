package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
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

type HandlerError struct {
	status  int
	message *string
	visible bool
}

func (e *HandlerError) Error() string {
	return fmt.Sprintf("%d %s", e.status, *e.message)
}

func WrapError(err error, status int, visible bool) *HandlerError {
	errMsg := err.Error()
	return &HandlerError{status: status, visible: visible, message: &errMsg}
}

func wrapHandler(
	handler func(ctx *ServerContext, r *http.Request) ([]byte, *HandlerError),
	ctx *ServerContext,
	contentType string,
	authenticated bool,
) http.HandlerFunc {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if authenticated {
			if err := AuthenticateRequest(request, responseWriter, ctx); err != nil {
				log.Printf(err.Error())
				return
			}
		}
		ctx.stateMutex.Lock()
		defer ctx.stateMutex.Unlock()
		log.Printf("From %s: %s %s\n", request.RemoteAddr, request.Method, request.URL.Path)
		result, err := handler(ctx, request)
		if err != nil {
			// HTTP error response
			responseWriter.WriteHeader(err.status)
			if err.visible {
				responseWriter.Write([]byte(*err.message))
			}
		} else if result != nil {
			// HTTP success response with a body
			responseWriter.Header().Set("Content-Type", contentType)
			responseWriter.Write(result)
		} else {
			// HTTP success response with no body
			responseWriter.WriteHeader(http.StatusOK)
		}
	})
}

// GET /
func handleGetRoot(ctx *ServerContext, r *http.Request) ([]byte, *HandlerError) {
	var sortedPeersList []WgPeer
	for _, peer := range ctx.confFile.Peers {
		sortedPeersList = append(sortedPeersList, peer)
	}
	sort.Slice(sortedPeersList, func(i, j int) bool { return sortedPeersList[i].Comment < sortedPeersList[j].Comment })
	var tplResult bytes.Buffer
	if err := indexHtmlTpl.Execute(&tplResult, map[string]any{
		"peers": sortedPeersList,
	}); err != nil {
		return nil, WrapError(err, 500, false)
	} else {
		return tplResult.Bytes(), nil
	}
}

// PUT /peer
func handleEditPeer(ctx *ServerContext, r *http.Request) ([]byte, *HandlerError) {
	requestBytes, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		return nil, WrapError(readErr, 400, false)
	}
	var requestPeerObj WgPeer
	if err := json.Unmarshal(requestBytes, &requestPeerObj); err != nil {
		return nil, WrapError(err, 400, true)
	}
	if err := requestPeerObj.validate(); err != nil {
		return nil, WrapError(err, 400, true)
	}
	if _, ok := ctx.confFile.Peers[requestPeerObj.Pubkey]; ok {
		ctx.confFile.Peers[requestPeerObj.Pubkey] = requestPeerObj
	} else {
		return nil, WrapError(fmt.Errorf("Peer not found: %s", requestPeerObj.Pubkey), 404, true)
	}
	if err := ctx.confFile.save(ctx.config.Wireguard.ifname); err != nil {
		return nil, WrapError(err, 500, false)
	}
	return nil, nil
}

// POST /peer
func handleCreatePeer(ctx *ServerContext, r *http.Request) ([]byte, *HandlerError) {
	requestBytes, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		return nil, WrapError(readErr, 400, false)
	}
	var requestPeerObj WgPeer
	if err := json.Unmarshal(requestBytes, &requestPeerObj); err != nil {
		return nil, WrapError(err, 400, true)
	}
	if err := requestPeerObj.validate(); err != nil {
		return nil, WrapError(err, 400, true)
	}
	if _, ok := ctx.confFile.Peers[requestPeerObj.Pubkey]; ok {
		return nil, WrapError(fmt.Errorf("Peer already exists"), 400, true)
	} else {
		ctx.confFile.Peers[requestPeerObj.Pubkey] = requestPeerObj
	}
	if err := ctx.confFile.save(ctx.config.Wireguard.ifname); err != nil {
		return nil, WrapError(err, 500, true)
	}
	return nil, nil
}

// DELETE /peer/{pubkey}
// pubkey must be encoded as URL-safe base64 (and not the standard Base64 WireGuard keys are usually encoded as)
func handleDeletePeer(ctx *ServerContext, r *http.Request) ([]byte, *HandlerError) {
	pubkeyBase64Url := r.PathValue("pubkey")
	pubkeyDecoded, decodeErr := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(pubkeyBase64Url)
	if decodeErr != nil {
		return nil, WrapError(decodeErr, 400, true)
	}
	pubkey := base64.StdEncoding.EncodeToString(pubkeyDecoded)
	delete(ctx.confFile.Peers, pubkey)
	if err := ctx.confFile.save(ctx.config.Wireguard.ifname); err != nil {
		return nil, WrapError(err, 500, false)
	}
	return nil, nil
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
func handleGetPeerEnrolmentPage(ctx *ServerContext, r *http.Request) ([]byte, *HandlerError) {
	pubkeyPreimageBase64Url := r.PathValue("pubkeyPreimage")
	pubkeyPreimageDecoded, decodeErr := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(pubkeyPreimageBase64Url)
	if decodeErr != nil {
		return nil, WrapError(decodeErr, 400, true)
	}
	pubkeyBytes := sha256.Sum256([]byte(pubkeyPreimageDecoded))
	pubkey := base64.StdEncoding.EncodeToString(pubkeyBytes[:])

	if peer, ok := ctx.confFile.Peers[pubkey]; ok {
		peerAddrs, err := computePeerIPs(peer.AllowedIps, ctx.confFile)
		if err != nil {
			return nil, WrapError(err, 500, false)
		}
		var response bytes.Buffer
		if err := enrolmentHtmlTpl.Execute(&response, map[string]any{
			"peerAddresses":      peerAddrs,
			"pubkeyPreimage":     pubkeyPreimageBase64Url,
			"advertisedDNS":      strings.Join(ctx.config.Advertise.Dns, ","),
			"serverPublicKey":    ctx.config.Advertise.PublicKey,
			"advertisedNetworks": strings.Join(ctx.config.Advertise.Subnets, ","),
			"advertisedEndpoint": ctx.config.Advertise.Endpoint,
		}); err != nil {
			return nil, WrapError(err, 500, false)
		} else {
			return response.Bytes(), nil
		}
	} else {
		return nil, WrapError(fmt.Errorf("Not Found"), 404, false)
	}
}

// PUT /peer/{pubkeyPreimage}
func handleEnrolPeer(ctx *ServerContext, r *http.Request) ([]byte, *HandlerError) {
	type SetPeerPubkeyRequest struct {
		NewPubKey string
		NewPSK    *string
	}

	pubkeyPreimageBase64Url := r.PathValue("pubkeyPreimage")
	pubkeyPreimageDecoded, decodeErr := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(pubkeyPreimageBase64Url)
	if decodeErr != nil {
		return nil, WrapError(decodeErr, 400, false)
	}
	pubkeyBytes := sha256.Sum256([]byte(pubkeyPreimageDecoded))
	pubkey := base64.StdEncoding.EncodeToString(pubkeyBytes[:])

	// The logic behind peer enrolment is as follows:
	// - The client must provide a SHA256 preimage of the peer's public key.
	// - This proves that the PublicKey field is not a real public key, but a "pending" peer
	// - Thus possession of the key preimage allows you to change the pubkey (and only the pubkey)

	if peerObj, ok := ctx.confFile.Peers[pubkey]; ok {
		requestBytes, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			return nil, WrapError(readErr, 400, false)
		}
		var requestObj SetPeerPubkeyRequest
		if err := json.Unmarshal(requestBytes, &requestObj); err != nil {
			return nil, WrapError(err, 400, true)
		}
		if err := validateWireguardKey(requestObj.NewPubKey); err != nil {
			return nil, WrapError(err, 400, true)
		}
		if requestObj.NewPSK != nil {
			if err := validateWireguardKey(requestObj.NewPubKey); err != nil {
				return nil, WrapError(err, 400, true)
			}
		}
		delete(ctx.confFile.Peers, pubkey)
		peerObj.Pubkey = requestObj.NewPubKey
		peerObj.PresharedKey = requestObj.NewPSK
		ctx.confFile.Peers[requestObj.NewPubKey] = peerObj
		if err := ctx.confFile.save(ctx.config.Wireguard.ifname); err != nil {
			return nil, WrapError(err, 500, false)
		}
	} else {
		return nil, WrapError(fmt.Errorf("Not Found"), 404, true)
	}
	return nil, nil
}

func listenAndServe(ctx *ServerContext) {
	// Admin panel functions
	http.HandleFunc("GET /", wrapHandler(handleGetRoot, ctx, "text/html", true))
	http.HandleFunc("PUT /peer", wrapHandler(handleEditPeer, ctx, "text/plain", true))
	http.HandleFunc("POST /peer", wrapHandler(handleCreatePeer, ctx, "text/plain", true))
	http.HandleFunc("DELETE /peer/{pubkey}", wrapHandler(handleDeletePeer, ctx, "text/plain", true))
	// Peer enrolment
	http.HandleFunc("GET /peer/{pubkeyPreimage}", wrapHandler(handleGetPeerEnrolmentPage, ctx, "text/html", false))
	http.HandleFunc("PUT /peer/{pubkeyPreimage}", wrapHandler(handleEnrolPeer, ctx, "text/plain", false))

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
