package server

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
	"net/mail"
	"net/netip"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"thebasstoon.com/wgenrol/internal/storage"
	"thebasstoon.com/wgenrol/internal/wireguard"
)

// decodePathKey decodes a base64url (unpadded) path value into a Key.
func decodePathKey(pathValue string) (wireguard.Key, *handlerError) {
	keyBytes, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(pathValue)
	if err != nil {
		return wireguard.Key{}, wrapError(err, 400, true)
	}
	key, err := wireguard.KeyFromBytes(keyBytes)
	if err != nil {
		return wireguard.Key{}, wrapError(err, 400, true)
	}
	return key, nil
}

// sendMail routes the invite-email delivery through the SendMailFn hook if
// one is set, net/smtp otherwise.
func sendMail(ctx *ServerContext, addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	if ctx.SendMailFn != nil {
		return ctx.SendMailFn(addr, auth, from, to, msg)
	}
	return smtp.SendMail(addr, auth, from, to, msg)
}

// applyPeerSet builds a DeviceApplyFn that pushes the given peer list to the
// WireGuard device configured in the app's config. The store invokes it
// before committing, so device state and store stay consistent.
func applyPeerSet(ctx *ServerContext) storage.DeviceApplyFn {
	return func(peers []wireguard.WgPeer) error {
		return wireguard.ApplyPeerConfig(*ctx.Config.Wireguard.Ifname, peers)
	}
}

// GET /
func handleGetRoot(ctx *ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *handlerError) {
	peers, err := ctx.Store.ListPeers()
	if err != nil {
		return nil, wrapError(err, 500, false)
	}
	pendingPeers, err := ctx.Store.ListPendingPeers()
	if err != nil {
		return nil, wrapError(err, 500, false)
	}
	var tplResult bytes.Buffer
	if err := indexHtmlTpl.Execute(&tplResult, map[string]any{
		"peers":        peers,
		"pendingPeers": pendingPeers,
		"smtpEnabled":  ctx.Config.Smtp.Enabled,
	}); err != nil {
		return nil, wrapError(err, 500, false)
	} else {
		return tplResult.Bytes(), nil
	}
}

// PUT /peer
func handleEditPeer(ctx *ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *handlerError) {
	type EditPeerRequest struct {
		Pubkey  string
		Comment string
	}
	requestBytes, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		return nil, wrapError(readErr, 400, false)
	}
	var requestPeerObj EditPeerRequest
	if err := json.Unmarshal(requestBytes, &requestPeerObj); err != nil {
		return nil, wrapError(err, 400, true)
	}
	pubkey, err := wireguard.DecodeWireguardKey(requestPeerObj.Pubkey)
	if err != nil {
		return nil, wrapError(err, 400, true)
	}
	if err := ctx.Store.UpdatePeerComment(pubkey, requestPeerObj.Comment); err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return nil, wrapError(fmt.Errorf("Peer not found: %s", requestPeerObj.Pubkey), 404, true)
		}
		return nil, wrapError(err, 500, false)
	}
	return nil, nil
}

// PUT /pending/{tokenHash}
// Adjusts the name and AllowedIPs of a pending enrollment before the peer
// claims it.
func handleEditPending(ctx *ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *handlerError) {
	type EditPendingRequest struct {
		Comment    string
		AllowedIPs []string
	}
	tokenHash, herr := decodePathKey(r.PathValue("tokenHash"))
	if herr != nil {
		return nil, herr
	}
	requestBytes, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		return nil, wrapError(readErr, 400, false)
	}
	var requestObj EditPendingRequest
	if err := json.Unmarshal(requestBytes, &requestObj); err != nil {
		return nil, wrapError(err, 400, true)
	}
	allowedIPs := make([]netip.Prefix, 0, len(requestObj.AllowedIPs))
	for _, entry := range requestObj.AllowedIPs {
		prefix, err := netip.ParsePrefix(strings.Trim(entry, " "))
		if err != nil {
			return nil, wrapError(fmt.Errorf("Invalid request: %s is not a valid network", entry), 400, true)
		}
		allowedIPs = append(allowedIPs, prefix.Masked())
	}
	if len(allowedIPs) <= 0 {
		return nil, wrapError(fmt.Errorf("AllowedIPs cannot be empty."), 400, true)
	}
	// Guard against IP overlaps with existing reservations. This runs
	// under StateMutex, so the check and the update are atomic in-process.
	peers, err := ctx.Store.ListPeers()
	if err != nil {
		return nil, wrapError(err, 500, false)
	}
	pending, err := ctx.Store.ListPendingPeers()
	if err != nil {
		return nil, wrapError(err, 500, false)
	}
	reserved := make([]netip.Prefix, 0)
	for _, peer := range peers {
		reserved = append(reserved, peer.AllowedIps...)
	}
	for _, entry := range pending {
		if entry.TokenHash == tokenHash {
			continue
		}
		reserved = append(reserved, entry.AllowedIps...)
	}
	for _, newPrefix := range allowedIPs {
		for _, r := range reserved {
			if r.Contains(newPrefix.Addr()) || newPrefix.Contains(r.Addr()) {
				return nil, wrapError(fmt.Errorf("Invalid request: %s overlaps with an existing reservation", newPrefix.String()), 400, true)
			}
		}
	}
	if err := ctx.Store.UpdatePendingPeer(tokenHash, requestObj.Comment, allowedIPs); err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return nil, wrapError(fmt.Errorf("Pending enrollment not found."), 404, true)
		}
		return nil, wrapError(err, 500, false)
	}
	return nil, nil
}

// DELETE /pending/{tokenHash}
func handleDeletePending(ctx *ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *handlerError) {
	tokenHash, herr := decodePathKey(r.PathValue("tokenHash"))
	if herr != nil {
		return nil, herr
	}
	if err := ctx.Store.DeletePendingPeer(tokenHash); err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return nil, wrapError(fmt.Errorf("Pending enrollment not found."), 404, true)
		}
		return nil, wrapError(err, 500, false)
	}
	return nil, nil
}

// DELETE /peer/{pubkey}
// pubkey must be encoded as URL-safe base64 (and not the standard Base64 WireGuard keys are usually encoded as)
func handleDeletePeer(ctx *ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *handlerError) {
	pubkey, herr := decodePathKey(r.PathValue("pubkey"))
	if herr != nil {
		return nil, herr
	}
	if err := ctx.Store.DeletePeer(pubkey, applyPeerSet(ctx)); err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return nil, wrapError(fmt.Errorf("Peer not found."), 404, true)
		}
		return nil, wrapError(err, 500, false)
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

func computeClientConfigAllowedIPs(peerAllowedIps []netip.Prefix, deviceNets []netip.Prefix) (*string, error) {
	ips := make([]netip.Addr, 0, len(peerAllowedIps))
	for _, network := range peerAllowedIps {
		ips = append(ips, getFirstIPInNetwork(network))
	}
	peerNetworksStr := make([]string, 0)
	for _, ip := range ips {
		for _, network := range deviceNets {
			if network.Contains(ip) {
				ipWithNet := netip.PrefixFrom(ip, network.Bits())
				peerNetworksStr = append(peerNetworksStr, ipWithNet.String())
			}
		}
	}
	if len(peerNetworksStr) == 0 {
		return nil, fmt.Errorf("Could not generate AllowedIPs for the client configs (intersection of device nets and the peer's allowed IPs is empty?)")
	}
	result := strings.Join(peerNetworksStr, ",")
	return &result, nil
}

// POST /pending
// Creates a pending enrollment: the peer's IP is reserved in the store, but
// nothing is applied to the WireGuard device until the peer enrolls with a
// real public key.
func handleCreatePending(ctx *ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *handlerError) {
	requestBytes, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		return nil, wrapError(readErr, 400, false)
	}
	type CreatePendingRequest struct {
		TokenHash        string
		Comment          string
		RegistrationLink *string
		UserEmail        *string
	}
	var requestPeerObj CreatePendingRequest
	if err := json.Unmarshal(requestBytes, &requestPeerObj); err != nil {
		return nil, wrapError(err, 400, true)
	}
	if requestPeerObj.UserEmail != nil && len(*requestPeerObj.UserEmail) > 0 {
		if _, err := mail.ParseAddress(*requestPeerObj.UserEmail); err != nil {
			return nil, wrapError(fmt.Errorf("Invalid request: %s is not a valid email", *requestPeerObj.UserEmail), 400, true)
		}
		if requestPeerObj.RegistrationLink == nil {
			return nil, wrapError(fmt.Errorf("Invalid request: RegistrationLink cannot be empty if UserEmail is specified"), 400, true)
		} else if _, err := url.ParseRequestURI(*requestPeerObj.RegistrationLink); err != nil {
			return nil, wrapError(fmt.Errorf("Invalid request: %s is not a valid link", *requestPeerObj.RegistrationLink), 400, true)
		}
	}
	tokenHash, err := wireguard.DecodeWireguardKey(requestPeerObj.TokenHash)
	if err != nil {
		return nil, wrapError(err, 400, true)
	}
	// Duplicate check before the (expensive) allocation, so a repeated
	// registration can fail without touching the WireGuard device.
	if _, ok, err := ctx.Store.GetPendingPeer(tokenHash); err != nil {
		return nil, wrapError(err, 500, false)
	} else if ok {
		return nil, wrapError(fmt.Errorf("A pending enrollment with this token hash already exists."), 400, true)
	}
	deviceNetsList, err := wireguard.GetDeviceNets(*ctx.Config.Wireguard.Ifname)
	if err != nil {
		return nil, wrapError(err, 500, false)
	}
	peers, err := ctx.Store.ListPeers()
	if err != nil {
		return nil, wrapError(err, 500, false)
	}
	pending, err := ctx.Store.ListPendingPeers()
	if err != nil {
		return nil, wrapError(err, 500, false)
	}
	allowedIPs, err := wireguard.AllocateAllowedIPs(deviceNetsList, peers, pending)
	if err != nil {
		return nil, wrapError(err, 400, true)
	}
	peerObj := wireguard.PendingPeer{
		TokenHash:  tokenHash,
		Comment:    requestPeerObj.Comment,
		AllowedIps: allowedIPs,
		CreatedAt:  time.Now(),
	}
	if err := ctx.Store.CreatePendingPeer(peerObj); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return nil, wrapError(err, 400, true)
		}
		if strings.Contains(err.Error(), "AllowedIPs cannot be empty") {
			return nil, wrapError(err, 400, true)
		}
		return nil, wrapError(err, 500, false)
	}
	if ctx.Config.Smtp.Enabled && requestPeerObj.UserEmail != nil && len(*requestPeerObj.UserEmail) > 0 {
		go func() {
			parsedMail, err := mail.ParseAddress(*requestPeerObj.UserEmail)
			if err == nil {
				log.Printf("Sending registration email to %s", parsedMail.Address)
				auth := smtp.PlainAuth("", *ctx.Config.Smtp.User, *ctx.Config.Smtp.Password, *ctx.Config.Smtp.Host)
				to := []string{parsedMail.Address}
				msg := fmt.Appendf(nil, "To: %s\r\n"+
					"Subject: [WgEnrol] Registration Link\r\n"+
					"\r\n"+
					"A new WireGuard account was created for you.\r\n"+
					"Click the following link to register: %s\r\n", parsedMail.Address, *requestPeerObj.RegistrationLink)
				if err := sendMail(ctx, fmt.Sprintf("%s:%d", *ctx.Config.Smtp.Host, *ctx.Config.Smtp.Port), auth, *ctx.Config.Smtp.From, to, msg); err != nil {
					log.Printf("Sending registration email to %s failed: %s", parsedMail.Address, err.Error())
				}
			} else {
				log.Printf("Sending registration email to %s failed: %s", *requestPeerObj.UserEmail, err.Error())
			}
		}()
	}
	return nil, nil
}

// GET /peer/{token}
// token is the Base64-URL-encoded enrollment token of a pending enrollment
// stored in the peer store. The store only receives its SHA-256 digest.
func handleGetPeerEnrolmentPage(ctx *ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *handlerError) {
	tokenBase64Url := r.PathValue("token")
	tokenBytes, decodeErr := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(tokenBase64Url)
	if decodeErr != nil {
		return nil, wrapError(decodeErr, 400, true)
	}
	tokenHashSum := sha256.Sum256(tokenBytes)
	tokenHash, err := wireguard.KeyFromBytes(tokenHashSum[:])
	if err != nil {
		return nil, wrapError(err, 500, false)
	}

	pendingObj, ok, err := ctx.Store.GetPendingPeer(tokenHash)
	if err != nil {
		return nil, wrapError(err, 500, false)
	} else if !ok {
		return nil, wrapError(fmt.Errorf("Not Found"), 404, false)
	}
	deviceNetsList, err := wireguard.GetDeviceNets(*ctx.Config.Wireguard.Ifname)
	if err != nil {
		return nil, wrapError(err, 500, false)
	}

	peerAddrs, err := computeClientConfigAllowedIPs(pendingObj.AllowedIps, deviceNetsList)
	if err != nil {
		return nil, wrapError(err, 500, false)
	}
	var response bytes.Buffer
	vpnNetworksStr := make([]string, 0, len(deviceNetsList))
	advertisedDNS := make([]string, 0, len(deviceNetsList))
	for _, network := range deviceNetsList {
		vpnNetworksStr = append(vpnNetworksStr, network.Masked().String())
		if ctx.Config.Advertise.AdvertiseDNS {
			advertisedDNS = append(advertisedDNS, network.Addr().String())
		}
	}
	advertisedPublicKey, err := wireguard.GetDevicePubkey(*ctx.Config.Wireguard.Ifname)
	if err != nil {
		return nil, wrapError(err, 500, false)
	}
	if err := enrolmentHtmlTpl.Execute(&response, map[string]any{
		"peerAddresses":      peerAddrs,
		"token":              tokenBase64Url,
		"advertisedDNS":      strings.Join(advertisedDNS, ","),
		"serverPublicKey":    advertisedPublicKey,
		"advertisedNetworks": strings.Join(append(vpnNetworksStr, ctx.Config.Advertise.AdditionalSubnets...), ","),
		"advertisedEndpoint": ctx.Config.Advertise.Endpoint,
	}); err != nil {
		return nil, wrapError(err, 500, false)
	}
	return response.Bytes(), nil
}

// PUT /peer/{token}
func handleEnrolPeer(ctx *ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *handlerError) {
	type SetPeerPubkeyRequest struct {
		NewPubKey string
		NewPSK    *string
	}

	tokenBase64Url := r.PathValue("token")
	tokenBytes, decodeErr := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(tokenBase64Url)
	if decodeErr != nil {
		return nil, wrapError(decodeErr, 400, false)
	}
	tokenHashSum := sha256.Sum256(tokenBytes)
	tokenHash, err := wireguard.KeyFromBytes(tokenHashSum[:])
	if err != nil {
		return nil, wrapError(err, 500, false)
	}

	// The logic behind peer enrollment is as follows:
	// - The client must present the enrollment token of a stored pending enrollment.
	// - The store only knows the token's SHA-256 digest, so possession of the token
	//   proves that the bearer of the link is allowed to claim the invite.
	// - The store promotes the pending enrollment to a real peer in one transaction and
	//   applies the new peer list to the device before committing.

	if _, ok, err := ctx.Store.GetPendingPeer(tokenHash); err != nil {
		return nil, wrapError(err, 500, false)
	} else if !ok {
		return nil, wrapError(fmt.Errorf("Not Found"), 404, true)
	}
	requestBytes, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		return nil, wrapError(readErr, 400, false)
	}
	var requestObj SetPeerPubkeyRequest
	if err := json.Unmarshal(requestBytes, &requestObj); err != nil {
		return nil, wrapError(err, 400, true)
	}
	newPubkey, err := wireguard.DecodeWireguardKey(requestObj.NewPubKey)
	if err != nil {
		return nil, wrapError(err, 400, true)
	}
	var psk *wireguard.Key
	if requestObj.NewPSK != nil {
		parsedPsk, err := wireguard.DecodeWireguardKey(*requestObj.NewPSK)
		if err != nil {
			return nil, wrapError(err, 400, true)
		}
		psk = &parsedPsk
	}
	if err := ctx.Store.PromotePendingPeer(tokenHash, newPubkey, psk, applyPeerSet(ctx)); err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return nil, wrapError(fmt.Errorf("Not Found"), 404, true)
		}
		if strings.Contains(err.Error(), "already exists") {
			return nil, wrapError(err, 400, true)
		}
		return nil, wrapError(err, 500, false)
	}
	return nil, nil
}

// GET /login
func handleGetLogin(ctx *ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *handlerError) {
	var tplResult bytes.Buffer
	if err := loginHtmlTpl.Execute(&tplResult, map[string]any{}); err != nil {
		return nil, wrapError(err, 500, false)
	} else {
		return tplResult.Bytes(), nil
	}
}

// POST /login
func handlePostLogin(ctx *ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *handlerError) {
	// TODO: Login rate limit per IP with backoff
	type LoginRequest struct {
		Username string
		Password string
	}
	requestBytes, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		return nil, wrapError(readErr, 400, false)
	}
	var requestObj LoginRequest
	if err := json.Unmarshal(requestBytes, &requestObj); err != nil {
		return nil, wrapError(fmt.Errorf("Malformed request"), 400, true)
	}

	passwordHash, ok := ctx.Config.Admin.Users[requestObj.Username]
	// To prevent timing attacks against the username, if it is not found, compare against a dummy hash
	if !ok {
		passwordHash = "$2a$08$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	}
	// I really hope the compiler doesn't optimize this away...
	if passwordMatchErr := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(requestObj.Password)); passwordMatchErr != nil || !ok {
		return nil, wrapError(fmt.Errorf("Wrong username or password"), 401, true)
	}

	newToken := rand.Text()
	if err := ctx.Sessions.CreateSession(newToken, time.Now().Add(time.Hour)); err != nil {
		return nil, wrapError(err, 500, false)
	}
	http.SetCookie(resp, &http.Cookie{
		Name:     "session",
		Value:    base64.URLEncoding.EncodeToString([]byte(newToken)),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   ctx.Config.Server.Tls.Enabled,
		Path:     "/",
	})
	// Housekeeping: expired sessions exist until pruned; login is the natural
	// low-frequency hook. Failures only cost a log line.
	if _, err := ctx.Sessions.DeleteExpiredSessions(time.Now()); err != nil {
		log.Printf("Pruning expired sessions failed: %s", err.Error())
	}

	return nil, nil
}

// POST /logout
func handlePostLogout(ctx *ServerContext, r *http.Request, resp http.ResponseWriter) ([]byte, *handlerError) {
	if token, err := getSessionToken(r); token != nil && err == nil {
		if err := ctx.Sessions.DeleteSession(*token); err != nil {
			// The cookie is cleared either way; a failed delete means the
			// session row would remain valid server-side, so this is a real 500.
			return nil, wrapError(err, 500, false)
		}
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
