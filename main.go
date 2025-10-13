package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/crypto/kdf"
	"github.com/arnika-project/arnika/kms"
	"github.com/arnika-project/arnika/net"
	wg "github.com/arnika-project/arnika/wireguard"
)

var (
	// allows to set version on build.
	Version string
	// allows to overwrite app name on build.
	APPName string
)

func setPSK(psk string, cfg *config.Config) error {
	if cfg.UsePQC() {
		pqcKey, err := kdf.GetPQCMasterKey(cfg.PQCPSKFile)
		if err != nil {
			return err
		}

		if psk == "" {
			psk, err = kdf.GetPQCSubkey(pqcKey, kdf.SubkeyPqcOnly)
		} else {
			psk, err = kdf.GetHybridKey(psk, pqcKey)
		}
		if err != nil {
			return err
		}

	}
	wireguard, err := wg.NewWireGuardHandler()
	if err != nil {
		return err
	}
	return wireguard.SetKey(cfg.WireGuardInterface, cfg.WireguardPeerPublicKey, psk)
}

func fibonacciRecursion(n int) int {
	if n <= 1 {
		return n
	} else if n > 11 {
		return 120
	}
	return fibonacciRecursion(n-1) + fibonacciRecursion(n-2)
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
	skipPush := make(chan bool)
	kmsAuth := kms.NewClientCertificateAuth(cfg.Certificate, cfg.PrivateKey, cfg.CACertificate)
	kmsServer := kms.NewKMSServer(cfg.KMSURL, int(cfg.KMSHTTPTimeout.Seconds()), kmsAuth)

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGTERM,
		syscall.SIGINT,
	)
	defer cancel()

	go listenIds(ctx, cfg, skipPush, kmsServer)
	go pushIds(cfg, skipPush, kmsServer)
	<-ctx.Done()
}

func listenIds(ctx context.Context, cfg *config.Config, skipPush chan<- bool, kmsServer *kms.KMSHandler) {
	result := make(chan net.ArnikaServerRequest)
	go net.ArnikaServer(ctx, cfg, result)

	for r := range result {
		go func() {
			skipPush <- true
		}()

		var psk string
		if r.KMSAvailable {
			// use KMS (+PQC)
			log.Println("<-- BACKUP: received KMS key_id: " + r.KeyID)
			key, err := kmsServer.GetKeyByID(r.KeyID)
			if err != nil {
				log.Println(err.Error())
				time.Sleep(time.Millisecond * 100)
				continue
			}
			psk = key.GetKey()
		} else if !r.KMSAvailable && cfg.KMSMode == config.KmsPQCFallback {
			// use PQC
			log.Println("<-- BACKUP: requested PQC fallback")
			psk = ""
		} else {
			log.Println("<-- BACKUP: requested PQC fallback mode which is forbidden by config. Aborting.")
			continue
		}

		err := setPSK(psk, cfg)
		if err != nil {
			log.Println(err.Error())
		}
	}
}

func pushIds(cfg *config.Config, skipPush <-chan bool, kmsServer *kms.KMSHandler) {
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	retriesKms := 0
	for {
		select {
		case <-skipPush:
		default:
			// get key_id and send
			log.Printf("--> MASTER: fetch key_id from %s\n", cfg.KMSURL)
			key, err := kmsServer.GetNewKey()

			var kmsKey string
			var peerRequest net.ArnikaServerRequest
			switch cfg.KMSMode {
			case config.KmsStrict:
				if err != nil {
					// retry KMS until success
					log.Println(err.Error())
					time.Sleep(time.Second * time.Duration(fibonacciRecursion((retriesKms+20)/10)))
					retriesKms++
					continue
				}
				peerRequest = net.ArnikaServerRequest{KMSAvailable: true, KeyID: key.GetID()}
				kmsKey = key.GetKey()

			case config.KmsPQCFallback:
				// use only PQC
				if err != nil {
					log.Println(err.Error())
					peerRequest = net.ArnikaServerRequest{KMSAvailable: false, KeyID: ""}
					kmsKey = ""
				} else {
					peerRequest = net.ArnikaServerRequest{KMSAvailable: true, KeyID: key.GetID()}
					kmsKey = key.GetKey()
				}
			}

			if peerRequest.KMSAvailable {
				if kmsKey == "" {
					log.Printf("obtained empty key from KMS, retrying")
					time.Sleep(time.Second * time.Duration(fibonacciRecursion((retriesKms+20)/10)))
					retriesKms++
					continue
				}
				log.Printf("--> MASTER: send key_id to %s\n", cfg.ServerAddress)
			} else {
				log.Printf("--> MASTER: KMS not available, requesting PQC-only mode with %s\n", cfg.ServerAddress)
			}
			retriesKms = 0

			if err := net.ArnikaClient(cfg, peerRequest); err != nil {
				log.Println(err.Error())
			}
			if err := setPSK(kmsKey, cfg); err != nil {
				log.Println(err.Error())
			}
		}
		<-ticker.C
	}
}
