package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/smtp"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type WgPeerDTO struct {
	Pubkey       string
	PresharedKey *string
	Comment      string
}

func (peerDTO *WgPeerDTO) fromDTO(ctx *ServerContext) (*WgPeer, error) {
	allowedIPs, err := ctx.FindSuitableAllowedIPs()
	if err != nil {
		return nil, err
	}
	return &WgPeer{
		Pubkey:       peerDTO.Pubkey,
		PresharedKey: peerDTO.PresharedKey,
		AllowedIps:   allowedIPs,
		Comment:      peerDTO.Comment,
	}, nil
}

// GET /
func handleGetRoot(ctx *ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *HandlerError) {
	var sortedPeersList []WgPeer
	for _, peer := range ctx.ConfFile.Peers {
		sortedPeersList = append(sortedPeersList, peer)
	}
	sort.Slice(sortedPeersList, func(i, j int) bool { return sortedPeersList[i].Comment < sortedPeersList[j].Comment })
	var tplResult bytes.Buffer
	if err := indexHtmlTpl.Execute(&tplResult, map[string]any{
		"peers":       sortedPeersList,
		"smtpEnabled": ctx.Config.Smtp.Enabled,
	}); err != nil {
		return nil, WrapError(err, 500, false)
	} else {
		return tplResult.Bytes(), nil
	}
}

// PUT /peer
func handleEditPeer(ctx *ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *HandlerError) {
	requestBytes, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		return nil, WrapError(readErr, 400, false)
	}
	var requestPeerObjDTO WgPeerDTO
	if err := json.Unmarshal(requestBytes, &requestPeerObjDTO); err != nil {
		return nil, WrapError(err, 400, true)
	}
	requestPeerObj, err := requestPeerObjDTO.fromDTO(ctx)
	if err != nil {
		return nil, WrapError(readErr, 400, true)
	}
	if err := requestPeerObj.validate(); err != nil {
		return nil, WrapError(err, 400, true)
	}
	if _, ok := ctx.ConfFile.Peers[requestPeerObj.Pubkey]; ok {
		ctx.ConfFile.Peers[requestPeerObj.Pubkey] = *requestPeerObj
	} else {
		return nil, WrapError(fmt.Errorf("Peer not found: %s", requestPeerObj.Pubkey), 404, true)
	}
	if err := ctx.Commit(); err != nil {
		return nil, WrapError(err, 500, false)
	}
	return nil, nil
}

// POST /peer
func handleCreatePeer(ctx *ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *HandlerError) {
	requestBytes, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		return nil, WrapError(readErr, 400, false)
	}
	type SetPeerPubkeyRequest struct {
		Peer             WgPeerDTO
		RegistrationLink *string
		UserEmail        *string
	}
	var requestPeerObj SetPeerPubkeyRequest
	if err := json.Unmarshal(requestBytes, &requestPeerObj); err != nil {
		return nil, WrapError(err, 400, true)
	}
	peerObj, err := requestPeerObj.Peer.fromDTO(ctx)
	if err != nil {
		return nil, WrapError(err, 400, true)
	}
	if err := peerObj.validate(); err != nil {
		log.Printf("Validation of %v failed.", requestPeerObj.Peer)
		return nil, WrapError(err, 400, true)
	}
	if _, ok := ctx.ConfFile.Peers[requestPeerObj.Peer.Pubkey]; ok {
		return nil, WrapError(fmt.Errorf("Peer already exists"), 400, true)
	} else {
		ctx.ConfFile.Peers[requestPeerObj.Peer.Pubkey] = *peerObj
	}
	if err := ctx.Commit(); err != nil {
		return nil, WrapError(err, 500, true)
	}
	if ctx.Config.Smtp.Enabled && requestPeerObj.UserEmail != nil && len(*requestPeerObj.UserEmail) > 0 {
		go func() {
			log.Printf("Sending registration email to %s", *requestPeerObj.UserEmail)
			auth := smtp.PlainAuth("", *ctx.Config.Smtp.User, *ctx.Config.Smtp.Password, *ctx.Config.Smtp.Host)
			to := []string{*requestPeerObj.UserEmail}
			msg := []byte(fmt.Sprintf("To: %s\r\n"+
				"Subject: [WgEnrol] Registration Link\r\n"+
				"\r\n"+
				"A new WireGuard account was created for you.\r\n"+
				"Click the following link to register: %s\r\n", *requestPeerObj.UserEmail, *requestPeerObj.RegistrationLink))
			if err := smtp.SendMail(fmt.Sprintf("%s:%d", *ctx.Config.Smtp.Host, *ctx.Config.Smtp.Port), auth, *ctx.Config.Smtp.From, to, msg); err != nil {
				log.Printf("Sending registration email to %s failed: %s", *requestPeerObj.UserEmail, err.Error())
			}
		}()
	}
	return nil, nil
}

// DELETE /peer/{pubkey}
// pubkey must be encoded as URL-safe base64 (and not the standard Base64 WireGuard keys are usually encoded as)
func handleDeletePeer(ctx *ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *HandlerError) {
	pubkeyBase64Url := r.PathValue("pubkey")
	pubkeyDecoded, decodeErr := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(pubkeyBase64Url)
	if decodeErr != nil {
		return nil, WrapError(decodeErr, 400, true)
	}
	pubkey := base64.StdEncoding.EncodeToString(pubkeyDecoded)
	if _, ok := ctx.ConfFile.Peers[pubkey]; !ok {
		return nil, WrapError(fmt.Errorf("Peer not found."), 404, true)
	}
	delete(ctx.ConfFile.Peers, pubkey)
	if err := ctx.Commit(); err != nil {
		return nil, WrapError(err, 500, false)
	}
	return nil, nil
}

func getFirstIPInNetwork(network netip.Prefix) netip.Addr {
	network = network.Masked()
	if network.IsSingleIP() {
		return network.Addr()
	} else {
		return network.Addr().Next()
	}
}

func computeClientConfigAllowedIPs(peerAllowedIps []netip.Prefix, deviceNets *[]netip.Prefix) (*string, error) {
	ips := make([]netip.Addr, 0, len(peerAllowedIps))
	for _, network := range peerAllowedIps {
		ips = append(ips, getFirstIPInNetwork(network))
	}
	peerNetworksStr := make([]string, 0)
	for _, ip := range ips {
		for _, network := range *deviceNets {
			if network.Contains(ip) {
				ipWithNet := netip.PrefixFrom(ip, network.Bits())
				peerNetworksStr = append(peerNetworksStr, ipWithNet.String())
			}
		}
	}
	result := strings.Join(peerNetworksStr, ",")
	return &result, nil
}

// GET /peer/{pubkeyPreimage}
// pubkeyPreimage must be a Base64-URL-encoded string and a valid preimage for a public key stored in the WireGuard configuration
func handleGetPeerEnrolmentPage(ctx *ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *HandlerError) {
	pubkeyPreimageBase64Url := r.PathValue("pubkeyPreimage")
	pubkeyPreimageDecoded, decodeErr := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(pubkeyPreimageBase64Url)
	if decodeErr != nil {
		return nil, WrapError(decodeErr, 400, true)
	}
	pubkeyBytes := sha256.Sum256([]byte(pubkeyPreimageDecoded))
	pubkey := base64.StdEncoding.EncodeToString(pubkeyBytes[:])
	deviceNets, err := ctx.GetDeviceNets()
	if err != nil {
		return nil, WrapError(err, 500, false)
	}

	if peer, ok := ctx.ConfFile.Peers[pubkey]; ok {
		peerAddrs, err := computeClientConfigAllowedIPs(peer.AllowedIps, deviceNets)
		if err != nil {
			return nil, WrapError(err, 500, false)
		}
		var response bytes.Buffer
		vpnNetworksStr := make([]string, 0, len(*deviceNets))
		advertisedDNS := make([]string, 0, len(*deviceNets))
		for _, network := range *deviceNets {
			vpnNetworksStr = append(vpnNetworksStr, network.Masked().String())
			if ctx.Config.Advertise.AdvertiseDNS {
				advertisedDNS = append(advertisedDNS, network.Addr().String())
			}
		}
		advertisedPublicKey, err := ctx.GetDevicePubkey()
		if err != nil {
			return nil, WrapError(err, 500, false)
		}
		if err := enrolmentHtmlTpl.Execute(&response, map[string]any{
			"peerAddresses":      peerAddrs,
			"pubkeyPreimage":     pubkeyPreimageBase64Url,
			"advertisedDNS":      strings.Join(advertisedDNS, ","),
			"serverPublicKey":    *advertisedPublicKey,
			"advertisedNetworks": strings.Join(append(vpnNetworksStr, ctx.Config.Advertise.AdditionalSubnets...), ","),
			"advertisedEndpoint": ctx.Config.Advertise.Endpoint,
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
func handleEnrolPeer(ctx *ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *HandlerError) {
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

	if peerObj, ok := ctx.ConfFile.Peers[pubkey]; ok {
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
		delete(ctx.ConfFile.Peers, pubkey)
		peerObj.Pubkey = requestObj.NewPubKey
		peerObj.PresharedKey = requestObj.NewPSK
		ctx.ConfFile.Peers[requestObj.NewPubKey] = peerObj
		if err := ctx.Commit(); err != nil {
			return nil, WrapError(err, 500, false)
		}
	} else {
		return nil, WrapError(fmt.Errorf("Not Found"), 404, true)
	}
	return nil, nil
}

// GET /login
func handleGetLogin(ctx *ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *HandlerError) {
	var tplResult bytes.Buffer
	if err := loginHtmlTpl.Execute(&tplResult, map[string]any{}); err != nil {
		return nil, WrapError(err, 500, false)
	} else {
		return tplResult.Bytes(), nil
	}
}

// POST /login
func handlePostLogin(ctx *ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *HandlerError) {
	type LoginRequest struct {
		Username string
		Password string
	}
	requestBytes, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		return nil, WrapError(readErr, 400, false)
	}
	var requestObj LoginRequest
	if err := json.Unmarshal(requestBytes, &requestObj); err != nil {
		return nil, WrapError(err, 400, true)
	}

	passwordHash, ok := ctx.Config.Admin.Users[requestObj.Username]
	if ok {
		if passwordMatchErr := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(requestObj.Password)); passwordMatchErr != nil {
			return nil, WrapError(fmt.Errorf("Wrong username or password"), 401, true)
		}
	} else {
		return nil, WrapError(fmt.Errorf("Wrong username or password"), 401, true)
	}

	newToken := rand.Text()
	ctx.ValidSessionTokens[newToken] = time.Now().Add(time.Hour)
	http.SetCookie(resp, &http.Cookie{
		Name:     "session",
		Value:    base64.URLEncoding.EncodeToString([]byte(newToken)),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   ctx.Config.Server.Tls.Enabled,
		Path:     "/",
	})

	tokensToRemove := make([]string, 0, len(ctx.ValidSessionTokens))
	for k, v := range ctx.ValidSessionTokens {
		if v.Compare(time.Now()) < 0 {
			tokensToRemove = append(tokensToRemove, k)
		}
	}
	for _, k := range tokensToRemove {
		delete(ctx.ValidSessionTokens, k)
	}

	return nil, nil
}

// POST /logout
func handlePostLogout(ctx *ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *HandlerError) {
	if token, err := GetSessionToken(r); token != nil && err == nil {
		delete(ctx.ValidSessionTokens, *token)
	}
	http.SetCookie(resp, &http.Cookie{
		Name:     "session",
		Value:    "",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   ctx.Config.Server.Tls.Enabled,
		Path:     "/",
		MaxAge:   0,
	})
	return nil, nil
}
