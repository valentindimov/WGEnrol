package main

import (
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"text/template"

	"gopkg.in/ini.v1"
)

//go:embed index.html
var indexHtmlTemplate string

//go:embed enrolment.html
var enrolmentHtmlTemplate string

type WgPeer struct {
	Pubkey       string
	PresharedKey *string
	AllowedIps   string
	Comment      string
}

type WgConf struct {
	filePath string
	file     *ini.File
	Peers    map[string]WgPeer
}

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

func validateWireguardKey(input string) error {
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return err
	}
	if len(decoded) != 32 {
		return fmt.Errorf("Invalid key: expected 32 bytes long, got %d bytes long.", len(decoded))
	}
	return nil
}

func (peer *WgPeer) validate() error {
	err := validateWireguardKey(peer.Pubkey)
	if err != nil {
		return err
	}
	if peer.PresharedKey != nil {
		err = validateWireguardKey(*peer.PresharedKey)
		if err != nil {
			return err
		}
	}
	if len(strings.Trim(peer.AllowedIps, " ")) > 0 {
		addrs := strings.SplitSeq(peer.AllowedIps, ",")
		for addr := range addrs {
			_, _, err = net.ParseCIDR(strings.Trim(addr, " "))
			if err != nil {
				return err
			}
		}
	} else {
		return fmt.Errorf("AllowedIPs cannot be empty.")
	}
	return nil
}

// Saves the INI file to a path atomically.
func saveIniFile(iniFile *ini.File, toPath string) error {
	toPath, err := filepath.Abs(toPath)
	if err != nil {
		return err
	}
	tempfile, err := os.CreateTemp(filepath.Dir(toPath), fmt.Sprintf("%s.swp", filepath.Base(toPath)))
	defer os.Remove(tempfile.Name())
	err = iniFile.SaveTo(tempfile.Name())
	if err != nil {
		return err
	}
	err = tempfile.Close()
	if err != nil {
		return err
	}
	err = os.Rename(tempfile.Name(), toPath)
	if err != nil {
		return err
	}
	return nil
}

func loadWgConf(filePathIn string) (*WgConf, error) {
	// Step 1: Load INI file
	options := ini.LoadOptions{
		AllowNonUniqueSections:     true,
		AllowShadows:               true,
		AllowDuplicateShadowValues: true,
		AllowBooleanKeys:           true,
	}
	filePathAbs, err := filepath.Abs(filePathIn)
	if err != nil {
		return nil, err
	}
	cfg, err := ini.LoadSources(options, filePathAbs)
	if err != nil {
		return nil, err
	}
	interfaceSection := cfg.Section("Interface")
	if interfaceSection == nil {
		return nil, errors.New("No Interface section found in the file.")
	}
	interfaceSection.Comment = "# This file is managed automatically.\n# Do not edit it, your changes may get overwritten."

	// Step 2: load peers from file
	peersMap := make(map[string]WgPeer)
	sections, err := cfg.SectionsByName("Peer")
	if err == nil && sections != nil {
		for _, section := range sections {
			if section.HasKey("PublicKey") {
				// Extract public key (all peers without one are ignored)
				val, err := section.GetKey("PublicKey")
				if err != nil {
					return nil, err
				}
				pubkey := val.Value()
				// Extract comment, make sure to strip the leading comment characters
				comment := section.Comment
				if strings.HasPrefix(comment, "#") || strings.HasPrefix(comment, ";") {
					comment = comment[1:]
				}
				comment = strings.TrimSpace(comment)
				// Extract AllowedIPs. This can be missing, in which case it's an empty list.
				allowedIPs := ""
				if section.HasKey("AllowedIPs") {
					val, err = section.GetKey("AllowedIPs")
					if err != nil {
						return nil, err
					}
					allowedIPs = strings.TrimSpace(val.Value())
				}
				// If the peer has a PresharedKey, read that too
				var presharedKey *string
				if section.HasKey("PresharedKey") {
					val, err = section.GetKey("PresharedKey")
					if err != nil {
						return nil, err
					}
					psk := strings.TrimSpace(val.Value())
					presharedKey = &psk
				}
				// Construct the peer object
				peersMap[pubkey] = WgPeer{
					Pubkey:       pubkey,
					PresharedKey: presharedKey,
					AllowedIps:   allowedIPs,
					Comment:      comment,
				}
			}
		}
	}

	// Finally: Write back the file to ensure the warning is displayed, and return
	err = saveIniFile(cfg, filePathAbs)
	if err != nil {
		return nil, err
	}
	result := WgConf{
		filePath: filePathAbs,
		file:     cfg,
		Peers:    peersMap,
	}
	return &result, nil
}

func (wgConf *WgConf) save(applyTo *string) error {
	// Edit the INI file with the contents of the peers map
	wgConf.file.DeleteSection("Peer")
	for _, peer := range wgConf.Peers {
		sec, err := wgConf.file.NewSection("Peer")
		if err != nil {
			return err
		}
		_, err = sec.NewKey("PublicKey", peer.Pubkey)
		if err != nil {
			return err
		}
		_, err = sec.NewKey("AllowedIPs", peer.AllowedIps)
		if err != nil {
			return err
		}
		if peer.PresharedKey != nil {
			_, err = sec.NewKey("PresharedKey", *peer.PresharedKey)
			if err != nil {
				return err
			}
		}
		sec.Comment = fmt.Sprintf("# %s", peer.Comment)
	}
	// Save the INI file.
	err := saveIniFile(wgConf.file, wgConf.filePath)
	if err != nil {
		return err
	}
	// If requested, apply the new configuration
	if applyTo != nil {
		// The below code is the equivalent of "/usr/bin/wg-quick strip ${filePath} | /usr/bin/wg syncconf ${applyTo} /dev/fd/0"
		/*
			stripCmd := exec.Command("/usr/bin/wg-quick", "strip", wgConf.filePath)
			stripCmdOut, err := stripCmd.StdoutPipe()
			if err != nil {
				return err
			}
			syncCmd := exec.Command("/usr/bin/wg", "syncconf", *applyTo, "/dev/fd/0")
			syncCmd.Stdin = stripCmdOut
			syncCmd.Start()
			stripCmd.Start()
			errSync := syncCmd.Wait()
			errStrip := stripCmd.Wait()
			if errStrip != nil {
				return errStrip
			}
			if errSync != nil {
				return errSync
			}
		*/
	}
	return nil
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

func computePeerIPs(peerAllowedIps string) (*string, error) {
	networks := make([]string, 0)
	if len(strings.Trim(peerAllowedIps, " ")) > 0 {
		addrs := strings.SplitSeq(peerAllowedIps, ",")
		for addr := range addrs {
			_, network, err := net.ParseCIDR(strings.Trim(addr, " "))
			if err != nil {
				return nil, err
			}
			ipWithNet := net.IPNet{
				IP:   getFirstIPInNetwork(network),
				Mask: network.Mask,
			}
			networks = append(networks, ipWithNet.String())
		}
	}
	result := strings.Join(networks, ",")
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
		peerAddrs, err := computePeerIPs(peer.AllowedIps)
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

		log.Print(string(requestBytes))
		log.Print(requestObj.NewPubKey)

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

func main() {
	indexHtmlTpl, err := template.New("index.html").Parse(indexHtmlTemplate)
	if err != nil {
		log.Fatal(err)
	}
	enrolmentHtmlTpl, err := template.New("enrolment.html").Parse(enrolmentHtmlTemplate)
	if err != nil {
		log.Fatal(err)
	}

	// Get parameters
	listenOnPtr := flag.String("listen", ":8080", "Address and port to bind on")
	ifnamePtr := flag.String("ifname", "wg0", "WireGuard interface to manage. It is assumed to already exist.")
	confFilePathPtr := flag.String("conffile", "/etc/wireguard/wg0.conf", "WireGuard config file to manage. It is assumed to already exist.")
	tlsCertPathPtr := flag.String("tlscert", "", "Path to TLS certificate (specify only if TLS should be enabled)")
	tlsKeyPathPtr := flag.String("tlskey", "", "Path to TLS certificate (specify only if TLS should be enabled)")
	advertisedEndpoint := flag.String("endpoint", "", "Endpoint under which clients can reach us (e.g. my.domain.name:51280)")
	advertisedNetworks := flag.String("networks", "", "Network to advertise to peers (e.g. 10.44.0.0/16)")
	advertisedPublicKey := flag.String("pubkey", "", "Public key to advertise to peers (see 'wg show' for that)")
	advertisedDNS := flag.String("dns", "", "DNS server to advertise to clients (optional)")
	flag.Parse()

	// Parameter validation
	if len(*tlsCertPathPtr) == 0 {
		tlsCertPathPtr = nil
	}
	if len(*tlsKeyPathPtr) == 0 {
		tlsKeyPathPtr = nil
	}
	if !((tlsKeyPathPtr == nil && tlsCertPathPtr == nil) || (tlsKeyPathPtr != nil && tlsCertPathPtr != nil)) {
		log.Fatal("-tlscert and -tlskey must both be specified if TLS should be used.")
	}
	if len(*advertisedEndpoint) == 0 || len(*advertisedNetworks) == 0 || len(*advertisedPublicKey) == 0 {
		log.Fatal("-endpoint, -networks, and -pubkey are required.")
	}
	err = validateWireguardKey(*advertisedPublicKey)
	if err != nil {
		log.Fatal(err)
	}
	_, _, err = net.SplitHostPort(*advertisedEndpoint)
	if err != nil {
		log.Fatal(err)
	}
	if len(strings.Trim(*advertisedNetworks, " ")) > 0 {
		addrs := strings.SplitSeq(*advertisedNetworks, ",")
		for addr := range addrs {
			_, _, err = net.ParseCIDR(strings.Trim(addr, " "))
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	// Create configuration
	confFile, err := loadWgConf(*confFilePathPtr)
	if confFile == nil || err != nil {
		log.Fatal(err)
	}
	ctx := ServerContext{
		indexHtmlTpl:        indexHtmlTpl,
		enrolmentHtmlTpl:    enrolmentHtmlTpl,
		ifname:              ifnamePtr,
		confFile:            confFile,
		advertisedEndpoint:  *advertisedEndpoint,
		advertisedNetworks:  *advertisedNetworks,
		advertisedPublicKey: *advertisedPublicKey,
	}
	if len(*advertisedDNS) > 0 {
		ctx.advertisedDNS = advertisedDNS
	}

	// Basic Auth parameters
	adminUser, adminUserFound := os.LookupEnv("ADMIN_USER")
	if !adminUserFound {
		log.Fatal("ADMIN_USER environment variable is required.")
	}
	adminPasswordHash, adminPasswordFound := os.LookupEnv("ADMIN_PASSWORD_HASH")
	if !adminPasswordFound {
		log.Fatal("ADMIN_PASSWORD_HASH environment variable is required.")
	}

	// Done, start the server
	log.Printf("Managing interface %s\n", *ifnamePtr)
	log.Printf("Listening on %s\n", *listenOnPtr)
	listenAndServe(listenOnPtr, tlsCertPathPtr, tlsKeyPathPtr, &ctx, adminUser, adminPasswordHash)
}
