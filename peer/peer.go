package peer

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/kdf"
	"github.com/arnika-project/arnika/kms"
	"github.com/arnika-project/arnika/net"
	"github.com/arnika-project/arnika/net/backoff"
	wg "github.com/arnika-project/arnika/wireguard"
)

type KMSError struct {
	Message string
}

func (e KMSError) Error() string {
	return fmt.Sprintf("failed when obtaining KMS key:%s", e.Message)
}

type ArnikaServer struct {
	cfg       *config.Config
	wgh       wg.VPN
	kmsServer kms.KeyStore
	netServer *net.NetServer
}

func NewServer(
	cfg *config.Config,
	wgh wg.VPN,
	kmsServer kms.KeyStore,
) ArnikaServer {
	return ArnikaServer{
		cfg:       cfg,
		wgh:       wgh,
		kmsServer: kmsServer,
	}
}

// Start the Arnika server; listen for messages from Arnika client and set PSK accordingly
// skipPush should be a buffered channel; this function does not wait for skipPush receivers
func (s *ArnikaServer) Start(ctx context.Context, skipPush chan<- bool) {
	result := make(chan net.ArnikaRequest)
	s.netServer = net.NewServer(s.cfg, result)
	// start network server
	go s.netServer.Start(ctx)
	// process incoming requests
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-result:
			if skipPush != nil {
				// do not block when skipPush has no receiver
				select {
				case skipPush <- true:
				default:
				}
			}
			s.processRequest(req)
		}
	}
}

func (s *ArnikaServer) processRequest(req net.ArnikaRequest) error {
	var (
		key *kms.Key
		err error
	)
	switch r := req.(type) {
	case net.RequestKMSKeyID:
		log.Println("<-- BACKUP: received key_id " + r.KeyID)
		key, err = s.kmsServer.GetKeyByID(r.KeyID)
	case net.RequestKMSFallback:
		if s.cfg.KMSMode != config.KmsLastFallback {
			log.Println("<-- BACKUP: fallback mode not configured!")
			return fmt.Errorf("received fallback message but fallback mode not configured")
		}
		log.Println("<-- BACKUP: received last KMS key request")
		key, err = s.kmsServer.GetFallbackKey()
	}
	if err != nil {
		log.Println(err.Error())
		time.Sleep(time.Millisecond * 100)
		return err
	}
	err = setPSK(key.GetKey(), s.wgh, s.cfg)
	if err != nil {
		log.Println(err.Error())
	}
	return nil
}

type ArnikaClient struct {
	cfg       *config.Config
	wgh       wg.VPN
	kmsServer kms.KeyStore
}

func NewClient(
	cfg *config.Config,
	wgh wg.VPN,
	kmsServer kms.KeyStore,
) ArnikaClient {
	return ArnikaClient{
		cfg,
		wgh,
		kmsServer,
	}
}

// Start the Arnika client; push messages for Arnika server and set PSK accordingly
func (c *ArnikaClient) Start(ctx context.Context, skipPush <-chan bool) {
	ticker := time.NewTicker(c.cfg.Interval)
	defer ticker.Stop()
	backoff := backoff.NewFibonacci()
	for {
		select {
		case <-ctx.Done():
			return
		case <-skipPush:
			// do not push and wait for next timer tick
			// TODO: ?
			cancellableWait(ctx, ticker.C)
		default:
			err := c.sendRequestAndSetPSK()
			if err != nil {
				log.Println("--> MASTER err:", err)
			}
			if errors.As(err, &KMSError{}) {
				ctxDoneErr := cancellableWait(ctx, time.After(backoff.Duration()))
				if ctxDoneErr != nil {
					return
				}
				backoff.Next()
				continue
			}
			// no KMS error, clear backoff
			backoff.Reset()
			cancellableWait(ctx, ticker.C)
		}
	}
}

func cancellableWait(ctx context.Context, tickerChan <-chan time.Time) error {
	select {
	case <-tickerChan:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// request key from KMS, notify peer and set PSK
// returns KMS error if KMS times out
// return other error if peer notification or setting PSK failed
func (c *ArnikaClient) sendRequestAndSetPSK() error {
	log.Printf("--> MASTER: fetch key_id from %s\n", c.cfg.KMSURL)
	var req net.ArnikaRequest
	key, err := c.kmsServer.GetNewKey()
	switch c.cfg.KMSMode {
	case config.KmsStrict:
		if err != nil {
			errKms := err
			err = c.wgh.DeactivatePeer()
			if err != nil {
				panic(fmt.Errorf("could not deactivate peer when KMS not available: %v", err))
			}
			return KMSError{errKms.Error()}
		}
		req = net.RequestKMSKeyID{KeyID: key.GetID()}

	case config.KmsLastFallback:
		if err != nil {
			key_, errLastKey := c.kmsServer.GetFallbackKey()
			key = key_
			if errLastKey != nil {
				return KMSError{fmt.Sprintf("cannot fallback, no KMS key ever received: %s", err.Error())}
			}
			log.Printf("--> MASTER: could not obtain KMS key, falling back to last valid KMS key\n")
			log.Printf("--> MASTER: falling back due to: %s\n", err.Error())
			req = net.RequestKMSFallback{}
		} else {
			req = net.RequestKMSKeyID{KeyID: key.GetID()}
		}
	}

	switch req.(type) {
	case net.RequestKMSKeyID:
		log.Printf("--> MASTER: send key_id to %s\n", c.cfg.ServerAddress)
	}
	errClient := net.NetClient(c.cfg, req)
	if errClient != nil {
		log.Printf("--> MASTER: error while contacting Arnika Server: %v\n", err)
	}

	// always set new PSK, even if NetClient was not succesful
	err = setPSK(key.GetKey(), c.wgh, c.cfg)
	if err != nil {
		return fmt.Errorf("cannot set PSK: %v; error during contacting Arnika: %v", err, errClient)
	}
	return errClient
}

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

func setPSK(psk string, wgh wg.VPN, cfg *config.Config) error {
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
