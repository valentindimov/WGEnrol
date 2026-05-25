package main

import (
	"flag"
	"log"
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
		confFile: confFile,
		config:   cfg,
	}

	// Done, start the server
	if cfg.Server.Tls.Enabled {
		log.Printf("Listening HTTPS on %s\n", *cfg.Server.ListenOn)
	} else {
		log.Printf("Listening HTTP on %s\n", *cfg.Server.ListenOn)
	}
	listenAndServe(&ctx)
}
