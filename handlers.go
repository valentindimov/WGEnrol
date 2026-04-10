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
	"net/http"
	"sort"
	"sync"
	"text/template"
)

//go:embed index.html
var indexHtmlTemplate string

//go:embed enrolment.html
var enrolmentHtmlTemplate string

type ServerContext struct {
	stateMutex       sync.Mutex
	ifname           *string
	confFile         *WgConf
	indexHtmlTpl     *template.Template
	enrolmentHtmlTpl *template.Template
}

type SetPeerPubkeyRequest struct {
	newPubKey string
	newPSK    *string
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
	for _, peer := range ctx.confFile.peers {
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
		http.Error(responseWriter, "Bad Request", http.StatusBadRequest)
		return nil
	}

	if _, ok := ctx.confFile.peers[requestPeerObj.Pubkey]; ok {
		ctx.confFile.peers[requestPeerObj.Pubkey] = requestPeerObj
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
		http.Error(responseWriter, "Bad Request", http.StatusBadRequest)
		return nil
	}
	var requestPeerObj WgPeer
	err = json.Unmarshal(requestBytes, &requestPeerObj)
	if err != nil {
		http.Error(responseWriter, "Bad Request", http.StatusBadRequest)
		return nil
	}

	if _, ok := ctx.confFile.peers[requestPeerObj.Pubkey]; ok {
		http.Error(responseWriter, "Peer already exists", http.StatusBadRequest)
		return nil
	} else {
		ctx.confFile.peers[requestPeerObj.Pubkey] = requestPeerObj
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
	pubkeyDecoded, err := base64.URLEncoding.DecodeString(pubkeyBase64Url)
	if err != nil {
		http.Error(responseWriter, "Bad Request", http.StatusBadRequest)
		return nil
	}
	pubkey := base64.StdEncoding.EncodeToString(pubkeyDecoded)

	delete(ctx.confFile.peers, pubkey)
	err = ctx.confFile.save(ctx.ifname)
	if err != nil {
		return err
	}

	responseWriter.WriteHeader(http.StatusOK)
	return nil
}

// GET /peer/{pubkeyPreimage}
func handleGetPeerEnrolmentPage(ctx *ServerContext, responseWriter http.ResponseWriter, request *http.Request) error {
	pubkeyPreimageBase64Url := request.PathValue("pubkeyPreimage")
	pubkeyPreimageDecoded, err := base64.URLEncoding.DecodeString(pubkeyPreimageBase64Url)
	if err != nil {
		http.Error(responseWriter, "Bad Request", http.StatusBadRequest)
		return nil
	}
	pubkeyBytes := sha256.Sum256([]byte(pubkeyPreimageDecoded))
	pubkey := base64.StdEncoding.EncodeToString(pubkeyBytes[:])

	if _, ok := ctx.confFile.peers[pubkey]; ok {
		responseWriter.Header().Set("Content-Type", "text/html")
		return ctx.indexHtmlTpl.Execute(responseWriter, map[string]any{
			"pubkeyPreimage": pubkeyPreimageBase64Url,
			"peer":           ctx.confFile.peers[pubkey],
		})
	} else {
		http.Error(responseWriter, "Not Found", http.StatusNotFound)
		return nil
	}
}

// PUT /peer/{pubkeyPreimage}
func handleEnrolPeer(ctx *ServerContext, responseWriter http.ResponseWriter, request *http.Request) error {
	pubkeyPreimageBase64Url := request.PathValue("pubkeyPreimage")
	pubkeyPreimageDecoded, err := base64.URLEncoding.DecodeString(pubkeyPreimageBase64Url)
	if err != nil {
		http.Error(responseWriter, "Bad Request", http.StatusBadRequest)
		return nil
	}
	pubkeyBytes := sha256.Sum256([]byte(pubkeyPreimageDecoded))
	pubkey := base64.StdEncoding.EncodeToString(pubkeyBytes[:])

	// The logic behind peer enrolment is as follows:
	// - The client must provide a SHA256 preimage of the peer's public key.
	// - This proves that the PublicKey field is not a real public key, but a "pending" peer
	// - Thus possession of the key preimage allows you to change the pubkey (and only the pubkey)

	if _, ok := ctx.confFile.peers[pubkey]; ok {
		requestBytes, err := io.ReadAll(request.Body)
		if err != nil || len(requestBytes) != 32 {
			http.Error(responseWriter, "Bad Request", http.StatusBadRequest)
			return nil
		}
		var requestObj SetPeerPubkeyRequest
		err = json.Unmarshal(requestBytes, &requestObj)
		if err != nil {
			http.Error(responseWriter, "Bad Request", http.StatusBadRequest)
			return nil
		}
		peerObj := ctx.confFile.peers[pubkey]
		delete(ctx.confFile.peers, pubkey)
		peerObj.Pubkey = requestObj.newPubKey
		peerObj.presharedKey = requestObj.newPSK
		ctx.confFile.peers[requestObj.newPubKey] = peerObj
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

func listenAndServe(listenOnPtr *string, ifname *string, confFilePath string, adminUser string, adminPasswordHash string) {
	indexHtmlTpl, err := template.New("index.html").Parse(indexHtmlTemplate)
	if err != nil {
		log.Fatal(err)
	}
	enrolmentHtmlTpl, err := template.New("enrolment.html").Parse(enrolmentHtmlTemplate)
	if err != nil {
		log.Fatal(err)
	}
	confFile, err := loadWgConf(confFilePath)
	if confFile == nil || err != nil {
		log.Fatal(err)
	}
	ctx := ServerContext{
		ifname:           ifname,
		confFile:         confFile,
		indexHtmlTpl:     indexHtmlTpl,
		enrolmentHtmlTpl: enrolmentHtmlTpl,
	}

	// Admin panel functions
	http.HandleFunc("GET /", basicAuthWrapper(wrapFuncAsHandler(handleGetRoot, &ctx), adminUser, adminPasswordHash))
	http.HandleFunc("PUT /peer", basicAuthWrapper(wrapFuncAsHandler(handleEditPeer, &ctx), adminUser, adminPasswordHash))
	http.HandleFunc("POST /peer", basicAuthWrapper(wrapFuncAsHandler(handleCreatePeer, &ctx), adminUser, adminPasswordHash))
	http.HandleFunc("DELETE /peer/{pubkey}", basicAuthWrapper(wrapFuncAsHandler(handleDeletePeer, &ctx), adminUser, adminPasswordHash))
	// Peer enrolment
	http.HandleFunc("GET /peer/{pubkeyPreimage}", wrapFuncAsHandler(handleGetPeerEnrolmentPage, &ctx))
	http.HandleFunc("PUT /peer/{pubkeyPreimage}", wrapFuncAsHandler(handleEnrolPeer, &ctx))

	http.ListenAndServe(*listenOnPtr, nil)
}
