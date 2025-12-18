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

type arnikaPeer struct {
	r *responder
	s *initiator
}

// NewPeer creates an Arnika peer who initiates/responds.
// Right now, it assigns initiator/responder statically.
// TODO:
//   - use proper dynamic initiator/responder, similar to Wireguard.
//     In case there are some assymetric KMS problems,
//     dynamic initiator/responder is better
//   - this would require advanced handling of race conditions of type
//     probably requiring adding timestamps
//     1. A->B: key_id1; takes long time
//     then
//     2. A<-B: key_id2; fast
//     3. A: ACK (for 2)
//     4. B: ACK (for 1)
func NewPeer(cfg *config.Config, wgh wg.VPN, kmsServer kms.KeyStore) (*arnikaPeer, error) {
	isInitiator := false
	switch {
	case cfg.ListenAddress != "" && cfg.ServerAddress != "":
		ourPubkey, err := wgh.GetPublicKey()
		if err != nil {
			return nil, fmt.Errorf("cannot get our wg pubkey: %w", err)
		}
		// lower pubkey wins initiator
		isInitiator = ourPubkey < cfg.WireguardPeerPublicKey
	case cfg.ListenAddress != "":
		isInitiator = false
	case cfg.ServerAddress != "":
		isInitiator = true
	default:
		return nil, fmt.Errorf("invalid Listen&Server Address")
	}
	p := &arnikaPeer{}
	if isInitiator {
		p.s = &initiator{cfg: cfg, wgh: wgh, kmsServer: kmsServer}
		log.Print("role: initiator")
	} else {
		p.r = &responder{cfg: cfg, wgh: wgh, kmsServer: kmsServer}
		log.Print("role: responder")
	}
	return p, nil
}

// Start start the peer; either as initiator or responder
// The call is blocking
func (p *arnikaPeer) Start(ctx context.Context) {
	if p.r != nil {
		p.r.Start(ctx)
	} else if p.s != nil {
		p.s.Start(ctx)
	}
}

type responder struct {
	cfg       *config.Config
	wgh       wg.VPN
	kmsServer kms.KeyStore
	netServer *net.NetServer
}

// Start our receiver; listen for messages from their initiator and set PSK accordingly
func (s *responder) Start(ctx context.Context) {
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
			s.processRequest(req)
		}
	}
}

func (s *responder) processRequest(req net.ArnikaRequest) error {
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
	err = setPSK(key, s.cfg, s.wgh)
	if err != nil {
		log.Println(err.Error())
	}
	return nil
}

type initiator struct {
	cfg       *config.Config
	wgh       wg.VPN
	kmsServer kms.KeyStore
}

// Start our initiator; push messages for their responder and set PSK accordingly
func (c *initiator) Start(ctx context.Context) {
	ticker := time.NewTicker(c.cfg.Interval)
	defer ticker.Stop()
	backoff := backoff.NewFibonacci()
	for {
		select {
		case <-ctx.Done():
			return
		default:
			err := c.sendRequestAndSetPSK()
			if err != nil {
				log.Println("--> MASTER err:", err)
			}
			if errors.As(err, &KMSError{}) {
				if cancellableWait(ctx, time.After(backoff.Duration())) != nil {
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

// request key from KMS, notify peer and set PSK
// returns KMS error if KMS times out
// return other error if peer notification or setting PSK failed
func (c *initiator) sendRequestAndSetPSK() error {
	log.Println("--> MASTER: fetch key_id")
	key, err := c.kmsServer.GetNewKey()

	var req net.ArnikaRequest
	if err == nil {
		// no error
		req = net.RequestKMSKeyID{KeyID: key.GetID()}
	} else {
		// new key error
		switch c.cfg.KMSMode {
		case config.KmsStrict:
			errKms := err
			err = c.wgh.DeactivatePeer()
			if err != nil {
				panic(fmt.Errorf("could not deactivate peer when KMS not available: %v", err))
			}
			return KMSError{errKms.Error()}

		case config.KmsLastFallback:
			fallbackKey, errFallback := c.kmsServer.GetFallbackKey()
			if errFallback != nil {
				err = c.wgh.DeactivatePeer()
				if err != nil {
					panic(fmt.Errorf("could not deactivate peer when KMS not available: %v", err))
				}
				return KMSError{fmt.Sprintf("cannot fallback, no KMS key ever received: %s", errFallback.Error())}
			}
			key = fallbackKey
			log.Printf("--> MASTER: could not obtain KMS key, falling back to last valid KMS key\n")
			log.Printf("--> MASTER: falling back due to: %s\n", err.Error())
			req = net.RequestKMSFallback{}
		}
	}

	switch req.(type) {
	case net.RequestKMSKeyID:
		log.Printf("--> MASTER: send key_id to %s\n", c.cfg.ServerAddress)
	}
	errClient := net.NetClient(c.cfg, req)
	if errClient != nil {
		log.Printf("--> MASTER: error while contacting Arnika Server: %v\n", errClient)
	}

	// always set new PSK, even if NetClient was not succesful
	err = setPSK(key, c.cfg, c.wgh)
	if err != nil {
		return fmt.Errorf("cannot set PSK: %v; error during contacting Arnika: %v", err, errClient)
	}
	return errClient
}

func cancellableWait(ctx context.Context, tickerChan <-chan time.Time) error {
	select {
	case <-tickerChan:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
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

func setPSK(qkd *kms.Key, cfg *config.Config, wgh wg.VPN) error {
	if cfg.UsePQC() {
		pQCKey, err := getPQCKey(cfg.PQCPSKFile)
		if err != nil {
			return err
		}
		psk, err := kdf.DeriveKey(qkd.GetKey(), pQCKey)
		if err != nil {
			return err
		}
		return wgh.SetKey(&kms.Key{ID: qkd.ID, Key: psk})
	}
	return wgh.SetKey(qkd)
}
