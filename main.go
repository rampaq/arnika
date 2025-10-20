package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/kdf"
	"github.com/arnika-project/arnika/kms"
	"github.com/arnika-project/arnika/net"
	"github.com/arnika-project/arnika/net/backoff"
	wg "github.com/arnika-project/arnika/wireguard"
)

var (
	// allows to set version on build.
	Version string
	// allows to overwrite app name on build.
	APPName string
)

func getPQCKey(pqcKeyFile string) (string, error) {
	file, err := os.Open(pqcKeyFile)
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Scan()
	return scanner.Text(), nil
}

func setPSK(psk string, wgh *wg.WireGuardHandler, cfg *config.Config) error {
	if cfg.UsePQC() {
		pQCKey, err := getPQCKey(cfg.PQCPSKFile)
		if err != nil {
			return err
		}
		psk, err = kdf.DeriveKey(psk, pQCKey)
		if err != nil {
			return err
		}
	}
	return wgh.SetKey(psk)
}

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
		skipPush = make(chan bool)
	} else {
		skipPush = nil
	}

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGTERM,
		syscall.SIGINT,
	)
	defer cancel()

	if cfg.ListenAddress != "" {
		go listenIds(ctx, cfg, wgh, kmsServer, skipPush)
	}

	if cfg.ServerAddress != "" {
		go pushIds(ctx, cfg, wgh, kmsServer, skipPush)
	}

	<-ctx.Done()
}

func listenIds(ctx context.Context, cfg *config.Config, wgh *wg.WireGuardHandler, kmsServer *kms.KMSHandler, skipPush chan<- bool) {
	result := make(chan net.ArnikaRequest)
	server := net.NewServer(cfg, result)
	go server.Start(ctx)

	for req := range result {
		if skipPush != nil {
			go func() {
				skipPush <- true
			}()
		}

		var (
			key *kms.Key
			err error
		)
		switch r := req.(type) {
		case net.RequestKMSKeyID:
			log.Println("<-- BACKUP: received key_id " + r.KeyID)
			key, err = kmsServer.GetKeyByID(r.KeyID)
		case net.RequestKMSFallback:
			log.Println("<-- BACKUP: received last KMS key request")
			key, err = kmsServer.GetLastKey()
		}
		if err != nil {
			log.Println(err.Error())
			time.Sleep(time.Millisecond * 100)
			continue
		}
		err = setPSK(key.GetKey(), wgh, cfg)
		if err != nil {
			log.Println(err.Error())
		}
	}
}

func pushIds(ctx context.Context, cfg *config.Config, wgh *wg.WireGuardHandler, kmsServer *kms.KMSHandler, skipPush chan bool) {
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	backoff := backoff.NewFibonacci()
	for {
		select {
		case <-ctx.Done():
			return
		case <-skipPush:
			// do not push and wait for next timer tick
		default:
			// request key from KMS, notify peer and set PSK
			log.Printf("--> MASTER: fetch key_id from %s\n", cfg.KMSURL)

			var req net.ArnikaRequest
			key, err := kmsServer.GetNewKey()
			switch cfg.KMSMode {
			case config.KmsStrict:
				if err != nil {
					backoff.Sleep()
					backoff.Next()
					continue
				}
				backoff.Reset()
				req = net.RequestKMSKeyID{KeyID: key.GetID()}

			case config.KmsLastFallback:
				if err != nil {
					key_, errLastKey := kmsServer.GetLastKey()
					key = key_
					if errLastKey != nil {
						log.Println("--> MASTER:", err.Error())
						log.Println("--> MASTER: cannot fall back to last KMS key, no valid key was ever received")
						log.Printf("--> MASTER: %v\n", err.Error())
						backoff.Sleep()
						backoff.Next()
						continue
					}
					log.Printf("--> MASTER: could not obtain KMS key, falling back to last valid KMS key")
					log.Printf("--> MASTER: %v\n", err.Error())
					req = net.RequestKMSFallback{}
				} else {
					req = net.RequestKMSKeyID{KeyID: key.GetID()}
				}
			}

			switch req.(type) {
			case net.RequestKMSKeyID:
				log.Printf("--> MASTER: send key_id to %s\n", cfg.ServerAddress)
			}
			err = net.ArnikaClient(cfg, req)
			if err != nil {
				log.Println(err.Error())
			}

			err = setPSK(key.GetKey(), wgh, cfg)
			if err != nil {
				log.Println(err.Error())
			}
		}
		<-ticker.C
	}
}
