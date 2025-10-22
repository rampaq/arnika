package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/kms"
	"github.com/arnika-project/arnika/peer"
	wg "github.com/arnika-project/arnika/wireguard"
)

var (
	// allows to set version on build.
	Version string
	// allows to overwrite app name on build.
	APPName string
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	versionLong := flag.Bool("version", false, "print version and exit")
	versionShort := flag.Bool("v", false, "alias for version")
	flag.Parse()
	if *versionShort || *versionLong {
		fmt.Printf("%s version %s\n", APPName, Version)
		os.Exit(0)
	}
	help := flag.Bool("help", false, "print usage and exit")
	flag.Parse()
	if *help {
		flag.Usage()
		os.Exit(0)
	}
	cfg, err := config.Parse()
	if err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	mainLoop(cfg)
}

func mainLoop(cfg *config.Config) {
	kmsAuth := kms.NewClientCertificateAuth(cfg.Certificate, cfg.PrivateKey, cfg.CACertificate)
	kmsServer := kms.NewKMSServer(cfg.KMSURL, int(cfg.KMSHTTPTimeout.Seconds()), kmsAuth)
	wgh, err := wg.SetupWireGuardIF(cfg.WireGuardInterface, cfg.WireguardPeerPublicKey)
	if err != nil {
		log.Fatalf("unable to setup wg interface: %v", err)
	}
	wgh.AddExpirationTimer(cfg.PSKExpirationInterval)

	// peers push key ids in cycles; skipPush skips pushing for current cycle
	var skipPush chan bool
	if cfg.ListenAddress != "" && cfg.ServerAddress != "" {
		skipPush = make(chan bool, 1)
	} else {
		skipPush = nil
	}

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGTERM,
		syscall.SIGINT,
	)
	defer cancel()

	if cfg.ListenAddress != "" {
		server := peer.NewServer(cfg, wgh, kmsServer)
		go server.Start(ctx, skipPush)
	}

	if cfg.ServerAddress != "" {
		client := peer.NewClient(cfg, wgh, kmsServer)
		go client.Start(ctx, skipPush)
	}

	<-ctx.Done()
}

