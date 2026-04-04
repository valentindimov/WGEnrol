package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"text/template"

	"gopkg.in/ini.v1"
)

//go:embed index.html.tpl
var indexHtmlTemplate string

func getRoot(tmpl *template.Template, stateMutex *sync.Mutex, numRequests *int) http.HandlerFunc {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		stateMutex.Lock()
		defer stateMutex.Unlock()
		*numRequests++

		log.Printf("From %s: %s %s\n", request.RemoteAddr, request.Method, request.URL.Path)

		tmplErr := tmpl.Execute(responseWriter, map[string]string{
			"numRequests": fmt.Sprintf("%d", numRequests),
		})
		if tmplErr != nil {
			http.Error(responseWriter, "Internal Server Error", http.StatusInternalServerError)
			log.Print(tmplErr)
		}
	})
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

func loadWgConf(path string) (*ini.File, error) {
	options := ini.LoadOptions{
		AllowNonUniqueSections:     true,
		AllowShadows:               true,
		AllowDuplicateShadowValues: true,
		AllowBooleanKeys:           true,
	}
	cfg, err := ini.LoadSources(options, "test.ini")
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func saveWgConf(wgConf *ini.File, path string) {
	wgConf.SaveTo(path)
}

func findPeerIndexByPubKey(wgConf *ini.File, pubKey string) (int, bool) {
	sections, err := wgConf.SectionsByName("Peer")
	if err != nil {
		return 0, false
	}
	for index, section := range sections {
		if section.HasKey("PublicKey") {
			val, err := section.GetKey("PublicKey")
			if err != nil {
				return 0, false
			}
			if val.Value() == pubKey {
				return index, true
			}
		}
	}
	return 0, false
}

func deletePeerByPubKey(wgConf *ini.File, pubKey string) error {
	for index, found := findPeerIndexByPubKey(wgConf, pubKey); found == true; index, found = findPeerIndexByPubKey(wgConf, pubKey) {
		err := wgConf.DeleteSectionWithIndex("Peer", index)
		if err != nil {
			return err
		}
	}
	return nil
}

func addOrReplacePeer(wgConf *ini.File, peerName string, peerPubKey string, peerAllowedIps string) error {
	sec, err := wgConf.NewSection("Peer")
	if err != nil {
		return err
	}
	_, err = sec.NewKey("PublicKey", peerPubKey)
	if err != nil {
		return err
	}
	_, err = sec.NewKey("AllowedIPs", peerAllowedIps)
	if err != nil {
		return err
	}
	sec.Comment = fmt.Sprintf("# %s", peerName)
	return nil
}

func main() {
	listenOnPtr := flag.String("listen", ":8080", "Address and port to bind on")
	ifnamePtr := flag.String("ifname", "wg0", "WireGuard interface to manage. Creates it if it's missing.")
	flag.Parse()

	adminUser, adminUserFound := os.LookupEnv("ADMIN_USER")
	if !adminUserFound {
		log.Fatal("ADMIN_USER environment variable is required.")
	}
	adminPasswordHash, adminPasswordFound := os.LookupEnv("ADMIN_PASSWORD_HASH")
	if !adminPasswordFound {
		log.Fatal("ADMIN_PASSWORD_HASH environment variable is required.")
	}

	tmpl, err := template.New("index.html").Parse(indexHtmlTemplate)
	if err != nil {
		log.Fatal(err)
	}

	signingKey := make([]byte, 32)
	rand.Read(signingKey)
	stateMutex := sync.Mutex{}
	numRequests := 0

	log.Printf("Managing interface %s\n", *ifnamePtr)
	log.Printf("Listening on %s\n", *listenOnPtr)
	http.HandleFunc("GET /", basicAuthWrapper(getRoot(tmpl, &stateMutex, &numRequests), adminUser, adminPasswordHash))
	http.ListenAndServe(*listenOnPtr, nil)
}
