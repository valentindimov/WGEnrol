package main

import (
	"crypto/rand"
	"flag"
	"log"
	"net/http"
	"os"
	"sync"
	"text/template"
)

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
