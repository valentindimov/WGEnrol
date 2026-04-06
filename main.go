package main

import (
	"flag"
	"log"
	"os"
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

	log.Printf("Managing interface %s\n", *ifnamePtr)
	log.Printf("Listening on %s\n", *listenOnPtr)

	listenAndServe(listenOnPtr, *ifnamePtr, adminUser, adminPasswordHash)
}
