package main

import (
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"text/template"
)

//go:embed index.html
var indexHtmlTemplate string

//go:embed enrolment.html
var enrolmentHtmlTemplate string

type ServerContext struct {
	stateMutex          sync.Mutex
	ifname              *string
	confFile            *WgConf
	indexHtmlTpl        *template.Template
	enrolmentHtmlTpl    *template.Template
	advertisedEndpoint  string
	advertisedNetworks  string
	advertisedPublicKey string
	advertisedDNS       *string
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

func wrapFuncAsHandler(next func(ctx *ServerContext, w http.ResponseWriter, r *http.Request) error, ctx *ServerContext) http.HandlerFunc {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		ctx.stateMutex.Lock()
		defer ctx.stateMutex.Unlock()
		log.Printf("From %s: %s %s\n", request.RemoteAddr, request.Method, request.URL.Path)
		err := next(ctx, responseWriter, request)
		if err != nil {
			http.Error(responseWriter, "Internal Server Error", http.StatusInternalServerError)
			log.Print(err)
		}
	})
}

// GET /
func handleGetRoot(ctx *ServerContext, responseWriter http.ResponseWriter, request *http.Request) error {
	responseWriter.Header().Set("Content-Type", "text/html")
	var sortedPeersList []WgPeer
	for _, peer := range ctx.confFile.Peers {
		sortedPeersList = append(sortedPeersList, peer)
	}
	sort.Slice(sortedPeersList, func(i, j int) bool { return sortedPeersList[i].Comment < sortedPeersList[j].Comment })
	return ctx.indexHtmlTpl.Execute(responseWriter, map[string]any{
		"peers": sortedPeersList,
	})
}

// PUT /peer
func handleEditPeer(ctx *ServerContext, responseWriter http.ResponseWriter, request *http.Request) error {
	requestBytes, err := io.ReadAll(request.Body)
	if err != nil {
		http.Error(responseWriter, "Bad Request", http.StatusBadRequest)
		return nil
	}
	var requestPeerObj WgPeer
	err = json.Unmarshal(requestBytes, &requestPeerObj)
	if err != nil {
		log.Print(err)
		http.Error(responseWriter, "Bad Request", http.StatusBadRequest)
		return nil
	}
	err = requestPeerObj.validate()
	if err != nil {
		log.Print(err)
		http.Error(responseWriter, "Bad Request", http.StatusBadRequest)
		return nil
	}

	if _, ok := ctx.confFile.Peers[requestPeerObj.Pubkey]; ok {
		ctx.confFile.Peers[requestPeerObj.Pubkey] = requestPeerObj
	} else {
		http.Error(responseWriter, "Not Found", http.StatusNotFound)
		return nil
	}
	err = ctx.confFile.save(ctx.ifname)
	if err != nil {
		return err
	}

	responseWriter.WriteHeader(http.StatusOK)
	return nil
}

// POST /peer
func handleCreatePeer(ctx *ServerContext, responseWriter http.ResponseWriter, request *http.Request) error {
	requestBytes, err := io.ReadAll(request.Body)
	if err != nil {
		log.Print(err)
		http.Error(responseWriter, "Bad Request", http.StatusBadRequest)
		return nil
	}
	var requestPeerObj WgPeer
	err = json.Unmarshal(requestBytes, &requestPeerObj)
	if err != nil {
		log.Print(err)
		http.Error(responseWriter, "Bad Request", http.StatusBadRequest)
		return nil
	}
	err = requestPeerObj.validate()
	if err != nil {
		log.Print(err)
		http.Error(responseWriter, "Bad Request", http.StatusBadRequest)
		return nil
	}

	if _, ok := ctx.confFile.Peers[requestPeerObj.Pubkey]; ok {
		http.Error(responseWriter, "Peer already exists", http.StatusBadRequest)
		return nil
	} else {
		ctx.confFile.Peers[requestPeerObj.Pubkey] = requestPeerObj
	}
	err = ctx.confFile.save(ctx.ifname)
	if err != nil {
		return err
	}

	responseWriter.WriteHeader(http.StatusOK)
	return nil
}

// DELETE /peer/{pubkey}
// pubkey must be encoded as URL-safe base64 (and not the standard Base64 WireGuard keys are usually encoded as)
func handleDeletePeer(ctx *ServerContext, responseWriter http.ResponseWriter, request *http.Request) error {
	pubkeyBase64Url := request.PathValue("pubkey")
	pubkeyDecoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(pubkeyBase64Url)
	if err != nil {
		log.Print(err)
		http.Error(responseWriter, "Bad Request", http.StatusBadRequest)
		return nil
	}
	pubkey := base64.StdEncoding.EncodeToString(pubkeyDecoded)

	delete(ctx.confFile.Peers, pubkey)
	err = ctx.confFile.save(ctx.ifname)
	if err != nil {
		return err
	}

	responseWriter.WriteHeader(http.StatusOK)
	return nil
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
func handleGetPeerEnrolmentPage(ctx *ServerContext, responseWriter http.ResponseWriter, request *http.Request) error {
	pubkeyPreimageBase64Url := request.PathValue("pubkeyPreimage")
	pubkeyPreimageDecoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(pubkeyPreimageBase64Url)
	if err != nil {
		log.Print(err)
		http.Error(responseWriter, "Bad Request", http.StatusBadRequest)
		return nil
	}
	pubkeyBytes := sha256.Sum256([]byte(pubkeyPreimageDecoded))
	pubkey := base64.StdEncoding.EncodeToString(pubkeyBytes[:])

	if peer, ok := ctx.confFile.Peers[pubkey]; ok {
		peerAddrs, err := computePeerIPs(peer.AllowedIps, ctx.confFile)
		if err != nil {
			return err
		}
		responseWriter.Header().Set("Content-Type", "text/html")
		return ctx.enrolmentHtmlTpl.Execute(responseWriter, map[string]any{
			"peerAddresses":      peerAddrs,
			"pubkeyPreimage":     pubkeyPreimageBase64Url,
			"advertisedDNS":      ctx.advertisedDNS,
			"serverPublicKey":    ctx.advertisedPublicKey,
			"advertisedNetworks": ctx.advertisedNetworks,
			"advertisedEndpoint": ctx.advertisedEndpoint,
		})
	} else {
		http.Error(responseWriter, "Not Found", http.StatusNotFound)
		return nil
	}
}

// PUT /peer/{pubkeyPreimage}
func handleEnrolPeer(ctx *ServerContext, responseWriter http.ResponseWriter, request *http.Request) error {
	type SetPeerPubkeyRequest struct {
		NewPubKey string
		NewPSK    *string
	}

	pubkeyPreimageBase64Url := request.PathValue("pubkeyPreimage")
	pubkeyPreimageDecoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(pubkeyPreimageBase64Url)
	if err != nil {
		log.Print(err)
		http.Error(responseWriter, "Bad Request", http.StatusBadRequest)
		return nil
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
			log.Print(err)
			http.Error(responseWriter, "Bad Request", http.StatusBadRequest)
			return nil
		}
		var requestObj SetPeerPubkeyRequest
		err = json.Unmarshal(requestBytes, &requestObj)
		if err != nil {
			log.Print(err)
			http.Error(responseWriter, "Bad Request", http.StatusBadRequest)
			return nil
		}
		err = validateWireguardKey(requestObj.NewPubKey)
		if err != nil {
			log.Print(err)
			http.Error(responseWriter, "Bad Request", http.StatusBadRequest)
			return nil
		}
		if requestObj.NewPSK != nil {
			err = validateWireguardKey(requestObj.NewPubKey)
			if err != nil {
				log.Print(err)
				http.Error(responseWriter, "Bad Request", http.StatusBadRequest)
				return nil
			}
		}
		delete(ctx.confFile.Peers, pubkey)
		peerObj.Pubkey = requestObj.NewPubKey
		peerObj.PresharedKey = requestObj.NewPSK
		ctx.confFile.Peers[requestObj.NewPubKey] = peerObj
		err = ctx.confFile.save(ctx.ifname)
		if err != nil {
			return err
		}
	} else {
		http.Error(responseWriter, "Not Found", http.StatusNotFound)
		return nil
	}

	responseWriter.WriteHeader(http.StatusOK)
	return nil
}

func listenAndServe(
	listenOnPtr *string,
	tlscert *string,
	tlskey *string,
	ctx *ServerContext,
	adminUser string,
	adminPasswordHash string,
) {
	// Admin panel functions
	http.HandleFunc("GET /", basicAuthWrapper(wrapFuncAsHandler(handleGetRoot, ctx), adminUser, adminPasswordHash))
	http.HandleFunc("PUT /peer", basicAuthWrapper(wrapFuncAsHandler(handleEditPeer, ctx), adminUser, adminPasswordHash))
	http.HandleFunc("POST /peer", basicAuthWrapper(wrapFuncAsHandler(handleCreatePeer, ctx), adminUser, adminPasswordHash))
	http.HandleFunc("DELETE /peer/{pubkey}", basicAuthWrapper(wrapFuncAsHandler(handleDeletePeer, ctx), adminUser, adminPasswordHash))
	// Peer enrolment
	http.HandleFunc("GET /peer/{pubkeyPreimage}", wrapFuncAsHandler(handleGetPeerEnrolmentPage, ctx))
	http.HandleFunc("PUT /peer/{pubkeyPreimage}", wrapFuncAsHandler(handleEnrolPeer, ctx))

	var err error
	if tlscert != nil && tlskey != nil {
		err = http.ListenAndServeTLS(*listenOnPtr, *tlscert, *tlskey, nil)
	} else {
		err = http.ListenAndServe(*listenOnPtr, nil)
	}
	if err != nil {
		log.Fatal(err)
	}
}
