package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/kdf"
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

func setPSK(psk string, cfg *config.Config) error {
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
	done := make(chan bool)
	skipPush := make(chan bool)
	kmsAuth := kms.NewClientCertificateAuth(cfg.Certificate, cfg.PrivateKey, cfg.CACertificate)
	kmsServer := kms.NewKMSServer(cfg.KMSURL, int(cfg.KMSHTTPTimeout.Seconds()), kmsAuth)

	go listenIds(cfg, skipPush, done, kmsServer)
	go pushIds(cfg, skipPush, kmsServer)
	<-done
}

func listenIds(cfg *config.Config, skipPush chan<- bool, done chan bool, kmsServer *kms.KMSHandler) {
	result := make(chan net.ArnikaServerRequest)
	go net.ArnikaServer(cfg.ListenAddress, result, done)

	for req := range result {
		go func() {
			skipPush <- true
		}()

		var (
			key *kms.Key
			err error
		)
		switch r := req.(type) {
		case net.ReqestKMSKeyID:
			log.Println("<-- BACKUP: received key_id " + r.KeyID)
			key, err = kmsServer.GetKeyByID(r.KeyID)
		case net.RequestKMSLast:
			log.Println("<-- BACKUP: received last KMS key request")
			key, err = kmsServer.GetLastKey()
		}
		if err != nil {
			log.Println(err.Error())
			time.Sleep(time.Millisecond * 100)
			continue
		}
		err = setPSK(key.GetKey(), cfg)
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

			var req net.ArnikaServerRequest
			key, err := kmsServer.GetNewKey()
			switch cfg.KMSMode {
			case config.KmsStrict:
				if err != nil {
					log.Println(err.Error())
					time.Sleep(time.Second * time.Duration(fibonacciRecursion((retriesKms+20)/10)))
					retriesKms++
					continue
				}
				retriesKms = 0
				req = net.ReqestKMSKeyID{KeyID: key.GetID()}

			case config.KmsLastFallback:
				if err != nil {
					key_, errLastKey := kmsServer.GetLastKey()
					key = key_
					if errLastKey != nil {
						log.Println("--> MASTER: cannot fall back to last KMS key, no valid key was ever received")
						log.Printf("--> MASTER: %v\n", err.Error())
						time.Sleep(time.Second * time.Duration(fibonacciRecursion((retriesKms+20)/10)))
						retriesKms++
						continue
					}
					log.Printf("--> MASTER: could not obtain KMS key, falling back to last valid KMS key")
					log.Printf("--> MASTER: %v\n", err.Error())
					req = net.RequestKMSLast{}
				} else {
					req = net.ReqestKMSKeyID{KeyID: key.GetID()}
				}
			default:
			}

			switch req.(type) {
			case net.ReqestKMSKeyID:
				log.Printf("--> MASTER: send key_id to %s\n", cfg.ServerAddress)
			}
			err = net.ArnikaClient(cfg, req)
			if err != nil {
				log.Println(err.Error())
			}
			err = setPSK(key.GetKey(), cfg)
			if err != nil {
				log.Println(err.Error())
			}
		}
		<-ticker.C
	}
}
