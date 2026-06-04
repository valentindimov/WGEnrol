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
	ctx, err := ParseConfigFile(*configPathPtr)
	if err != nil {
		log.Fatal(err)
	}

	// Done, start the server
	if ctx.Config.Server.Tls.Enabled {
		log.Printf("Listening HTTPS on %s\n", *ctx.Config.Server.ListenOn)
	} else {
		log.Printf("Listening HTTP on %s\n", *ctx.Config.Server.ListenOn)
	}
	listenAndServe(ctx)
}
