package main

import (
	"flag"
	"log"

	"thebasstoon.com/wgenrol/internal/config"
	"thebasstoon.com/wgenrol/internal/server"
	"thebasstoon.com/wgenrol/internal/storage"
	"thebasstoon.com/wgenrol/internal/storage/postgres"
	"thebasstoon.com/wgenrol/internal/storage/sqlite"
	"thebasstoon.com/wgenrol/internal/wireguard"
)

func main() {
	configPathPtr := flag.String("config", "", "Config file location")
	importPathPtr := flag.String("import", "", "Legacy wg-quick conf file to add peers from before starting the server")
	flag.Parse()
	if len(*configPathPtr) == 0 {
		log.Fatal("-config parameter is mandatory")
	}
	if err := run(*configPathPtr, *importPathPtr); err != nil {
		log.Fatal(err)
	}
}

// run wires up config, store, import or server. All failures are returned as
// errors; the serve path returns the (blocking) server's error as well.
func run(configPath, importPath string) error {
	cfg, err := config.ParseConfigFile(configPath)
	if err != nil {
		return err
	}
	store, sessions, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer store.Close()

	if len(importPath) > 0 {
		imported, skipped, err := runImport(store, importPath)
		if err != nil {
			return err
		}
		log.Printf("Import finished: %d peers imported, %d skipped.\n", imported, skipped)
		// Startup continues below: the imported peer list is applied to the
		// device and the server starts. Re-running with the same conf file
		// is safe (runImport skips existing peers).
	}

	ctx, err := server.NewContext(cfg, store, sessions)
	if err != nil {
		return err
	}

	ifname := *cfg.Wireguard.Ifname
	// Apply the stored peer list to the device on every startup, so the device
	// converges to the state in the database.
	peers, err := store.ListPeers()
	if err != nil {
		return err
	}
	if err := wireguard.ApplyPeerConfig(ifname, peers); err != nil {
		return err
	}

	// Done, start the server
	if ctx.Config.Server.Tls.Enabled {
		log.Printf("Listening HTTPS on %s\n", *ctx.Config.Server.ListenOn)
	} else {
		log.Printf("Listening HTTP on %s\n", *ctx.Config.Server.ListenOn)
	}
	return server.ListenAndServe(ctx)
}

// openStore connects to the storage backend defined in the config. The
// backend is normalized by config.ParseConfigFile; anything that is not
// postgres resolves to the (default) sqlite driver. The driver type
// implements both the peer and the session store.
func openStore(cfg *config.WgEnrolConfig) (storage.PeerStore, storage.SessionStore, error) {
	switch cfg.Storage.Backend {
	case "postgres":
		store, err := postgres.Open(*cfg.Storage.Dsn)
		return store, store, err
	default:
		store, err := sqlite.Open(*cfg.Storage.File)
		return store, store, err
	}
}

// runImport parses a wg-quick conf file and inserts all peers into the
// store. Peers that already exist (matched by public key) are skipped.
func runImport(store storage.PeerStore, importPath string) (imported, skipped int, err error) {
	peers, err := wireguard.ImportPeersFromINI(importPath)
	if err != nil {
		return 0, 0, err
	}
	for _, peer := range peers {
		if _, ok, getErr := store.GetPeer(peer.Pubkey); getErr != nil {
			return imported, skipped, getErr
		} else if ok {
			skipped++
			continue
		}
		if err := store.CreatePeer(peer); err != nil {
			return imported, skipped, err
		}
		imported++
	}
	return imported, skipped, nil
}
