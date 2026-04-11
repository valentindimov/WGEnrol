package main

import (
	"flag"
	"log"
	"net"
	"os"
	"strings"
	"text/template"
)

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
	ifnamePtr := flag.String("ifname", "", "WireGuard interface to manage. It is assumed to already exist.")
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
		confFile:            confFile,
		advertisedEndpoint:  *advertisedEndpoint,
		advertisedNetworks:  *advertisedNetworks,
		advertisedPublicKey: *advertisedPublicKey,
	}
	if len(*advertisedDNS) > 0 {
		ctx.advertisedDNS = advertisedDNS
	}
	if len(*ifnamePtr) > 0 {
		ctx.ifname = ifnamePtr
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
