package main

import (
	"flag"
	"log"
	"strings"
)

func main() {
	configPathPtr := flag.String("config", "", "Config file location")
	flag.Parse()
	if len(*configPathPtr) == 0 {
		log.Fatal("-config parameter is mandatory")
	}
	cfg, err := ParseConfigFile(*configPathPtr)
	if err != nil {
		log.Fatal(err)
	}

	// Create configuration
	confFile, err := loadWgConf(*cfg.Wireguard.ConfFile)
	if confFile == nil || err != nil {
		log.Fatal(err)
	}
	ctx := ServerContext{
		confFile:            confFile,
		ifname:              cfg.Wireguard.ifname,
		advertisedEndpoint:  *cfg.Advertise.Endpoint,
		advertisedNetworks:  strings.Join(cfg.Advertise.Subnets, ","),
		advertisedPublicKey: *cfg.Advertise.PublicKey,
	}
	if len(cfg.Advertise.Dns) > 0 {
		dnsAdvertisement := strings.Join(cfg.Advertise.Dns, ",")
		ctx.advertisedDNS = &dnsAdvertisement
	}

	// Done, start the server
	if cfg.Server.Tls.Enabled {
		log.Printf("Listening HTTPS on %s\n", *cfg.Server.ListenOn)
		listenAndServe(cfg.Server.ListenOn, cfg.Server.Tls.CertFile, cfg.Server.Tls.KeyFile, &ctx, *cfg.Admin.Username, *cfg.Admin.PasswordHash)
	} else {
		log.Printf("Listening HTTP on %s\n", *cfg.Server.ListenOn)
		listenAndServe(cfg.Server.ListenOn, nil, nil, &ctx, *cfg.Admin.Username, *cfg.Admin.PasswordHash)
	}
}
