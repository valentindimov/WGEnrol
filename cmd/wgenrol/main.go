package main

import (
	"flag"
	"log"

	"thebasstoon.com/wgenrol/internal/config"
	"thebasstoon.com/wgenrol/internal/server"
)

func main() {
	configPathPtr := flag.String("config", "", "Config file location")
	flag.Parse()
	if len(*configPathPtr) == 0 {
		log.Fatal("-config parameter is mandatory")
	}
	ctx, err := config.ParseConfigFile(*configPathPtr)
	if err != nil {
		log.Fatal(err)
	}
	if err := ctx.ConfFile.ApplyDeviceConfig(); err != nil {
		log.Fatal(err)
	}

	// Done, start the server
	if ctx.Config.Server.Tls.Enabled {
		log.Printf("Listening HTTPS on %s\n", *ctx.Config.Server.ListenOn)
	} else {
		log.Printf("Listening HTTP on %s\n", *ctx.Config.Server.ListenOn)
	}
	server.ListenAndServe(ctx)
}
