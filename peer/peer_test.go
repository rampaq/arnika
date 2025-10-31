package peer

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/kms"
	"github.com/google/uuid"
)

type MockVPN struct {
	Key       string
	Activated bool
	Pubkey    string
}

func (vpn *MockVPN) SetKey(s string) error {
	vpn.Key = s
	vpn.Activated = true
	return nil
}

func (vpn *MockVPN) DeactivatePeer() error {
	vpn.Activated = true
	return nil
}

func (vpn *MockVPN) GetPublicKey() (string, error) {
	if vpn.Pubkey == "" {
		return "", fmt.Errorf("pubkey not set")
	}
	return vpn.Pubkey, nil
}

type MockKeyStore struct {
	Keys      []kms.Key
	Activated bool
	mode      string
}

func (s *MockKeyStore) getNewRandomKey() (*kms.Key, error) {
	kid, err := uuid.NewRandom()
	check(err)
	kidStr := kid.String()
	rnd, err := randomBytes()
	check(err)
	key := kms.Key{ID: kidStr, Key: rnd}
	s.Keys = append(s.Keys, key)
	return &key, nil
}

func (s *MockKeyStore) GetNewKey() (*kms.Key, error) {
	switch s.mode {
	case "error":
		return nil, fmt.Errorf("intentional error in kms.GetNewKey")
	case "random":
		return s.getNewRandomKey()
	default:
		return &s.Keys[0], nil
	}
}

func (s *MockKeyStore) GetKeyByID(keyID string) (*kms.Key, error) {
	for _, key := range s.Keys {
		if key.GetID() == keyID {
			return &key, nil
		}
	}
	return nil, fmt.Errorf("no key with this ID")
}

func (s *MockKeyStore) GetFallbackKey() (*kms.Key, error) {
	if len(s.Keys) == 0 {
		return nil, fmt.Errorf("no previous key")
	}
	return &s.Keys[0], nil
}

// Test that Server correctly exits when context is cancelled
func TestServerExitsContextCancel(t *testing.T) {
	// port, err := getFreePort()
	// check(err)
	// addr := "localhost:" + strconv.Itoa(port)
	cfg := &config.Config{ListenAddress: "localhost:0"}
	vpn := new(MockVPN)
	keystore := &MockKeyStore{}
	server := responder{cfg: cfg, wgh: vpn, kmsServer: keystore}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Millisecond)
	defer cancel()
	finished := make(chan struct{})
	go func() {
		server.Start(ctx)
		close(finished)
	}()

	// wait for timeout
	<-ctx.Done()
	select {
	case <-finished:
	case <-time.After(2 * time.Millisecond):
		t.Errorf("ArnikaServer did not finish in time")
	}
}

// Test that Client correctly exits when no key is present and when context is cancelled
func TestClientExitsContextCancelWhenNoKey(t *testing.T) {
	// port, err := getFreePort()
	// check(err)
	// addr := "localhost:" + strconv.Itoa(port)
	cfg := &config.Config{ServerAddress: "localhost:0", Interval: time.Minute * 2}
	vpn := new(MockVPN)
	keystore := &MockKeyStore{mode: "error"}
	client := initiator{cfg, vpn, keystore}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Millisecond)
	defer cancel()
	finished := make(chan struct{})
	go func() {
		client.Start(ctx)
		close(finished)
	}()

	// wait for timeout
	<-ctx.Done()
	select {
	case <-finished:
	case <-time.After(2 * time.Millisecond):
		t.Errorf("ArnikaClient did not finish in time")
	}
}

// Test that Server correctly receives
func TestServerStrictHappyScenarioSingle(t *testing.T) {
	// TODO: better to invoke client.sendRequestAndSetPSK directly
	port, err := getFreePort()
	check(err)
	addr := "localhost:" + strconv.Itoa(port)

	cfg := &config.Config{
		ListenAddress: addr,
		ServerAddress: addr,
		KMSMode:       config.KmsStrict,
		Interval:      time.Second,
		PQCPSKFile:    "",
	}
	key := kms.Key{
		ID:  "bcbff446-c81b-4167-b40a-7c88f253ebda",
		Key: "q7eo2gEaZ48U/dI8qCFuLy5q0ySnkQGDJzCCZQQkfJg=",
	}
	keystore := &MockKeyStore{Keys: []kms.Key{key}}

	vpnServer := new(MockVPN)
	vpnClient := new(MockVPN)
	server := responder{cfg: cfg, wgh: vpnServer, kmsServer: keystore}
	client := initiator{cfg, vpnClient, keystore}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup

	// server
	wg.Add(1)
	go func() {
		server.Start(ctx)
		wg.Done()
	}()

	// client
	wg.Add(1)
	go func() {
		client.Start(ctx)
		wg.Done()
	}()

	bothFinished := make(chan struct{})
	go func() {
		wg.Wait()
		close(bothFinished)
	}()

	// wait for timeout
	<-ctx.Done()
	select {
	case <-bothFinished:
		if vpnClient.Key != key.GetKey() {
			t.Errorf("client did not correctly set VPN key")
		}
		if vpnServer.Key != key.GetKey() {
			t.Errorf("server did not correctly set VPN key")
		}
	case <-time.After(2 * time.Millisecond):
		t.Errorf("server & client did not finish in time")
	}
}

// Test that peers correctly determine which one should be initiator
func TestPeersNegotiateSamePSK10Times(t *testing.T) {
	portA, err := getFreePort()
	check(err)
	portB, err := getFreePort()
	check(err)
	addrA, addrB := "localhost:"+strconv.Itoa(portA), "localhost:"+strconv.Itoa(portB)

	pubkeyA, pubkeyB := "PHIHZhhgchOvxcqAw2uploHg2TiYxDHi97gojn82da0=", "1vbc1wm220ajhUbroI9bI1/Bt+fkleRQcDMxApfq+Dc="
	cfgA := &config.Config{
		ListenAddress:          addrA,
		ServerAddress:          addrB,
		KMSMode:                config.KmsStrict,
		Interval:               time.Millisecond, // repeat handshake every millisecond
		WireguardPeerPublicKey: pubkeyB,
		PQCPSKFile:             "",
	}
	cfgB := &config.Config{
		ListenAddress:          addrB,
		ServerAddress:          addrA,
		KMSMode:                config.KmsStrict,
		Interval:               time.Millisecond,
		WireguardPeerPublicKey: pubkeyA,
		PQCPSKFile:             "",
	}

	key1 := kms.Key{
		ID:  "bcbff446-c81b-4167-b40a-7c88f253ebda",
		Key: "q7eo2gEaZ48U/dI8qCFuLy5q0ySnkQGDJzCCZQQkfJg=",
	}
	key2 := kms.Key{
		ID:  "3aa9bf01-cd1b-4b20-8dda-bb2e72412106",
		Key: "dn9WEBER/0ZIn+mqmJcZZyMIiqeTreYz3dRiF1HZ4dE=",
	}
	// A
	keystoreA := &MockKeyStore{Keys: []kms.Key{key1, key2}}
	vpnA := &MockVPN{Pubkey: pubkeyA}
	peerA, err := NewPeer(cfgA, vpnA, keystoreA)
	check(err)

	// B
	keystoreB := &MockKeyStore{Keys: []kms.Key{key2, key1}}
	vpnB := &MockVPN{Pubkey: pubkeyB}
	peerB, err := NewPeer(cfgB, vpnB, keystoreB)
	check(err)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup

	// A
	wg.Add(1)
	go func() {
		peerA.Start(ctx)
		wg.Done()
	}()

	// B
	wg.Add(1)
	go func() {
		peerB.Start(ctx)
		wg.Done()
	}()

	bothFinished := make(chan struct{})
	go func() {
		wg.Wait()
		bothFinished <- struct{}{}
	}()

	// wait for timeout
	<-ctx.Done()
	select {
	case <-bothFinished:
		if vpnA.Key != vpnB.Key {
			t.Errorf("peer key mismatch: peerA set %s, peer B set %s", vpnA.Key, vpnB.Key)
		}
	case <-time.After(2 * time.Millisecond):
		t.Errorf("server & client did not finish in time")
	}
}

// keystore := &MockKeyStore{mode:"random"}
// key, err := keystore.GetNewKey()
// fmt.Printf("%#v", key)

// GetFreePort asks the kernel for a free open port that is ready to use
func getFreePort() (port int, err error) {
	var a *net.TCPAddr
	if a, err = net.ResolveTCPAddr("tcp", "localhost:0"); err == nil {
		var l *net.TCPListener
		if l, err = net.ListenTCP("tcp", a); err == nil {
			defer l.Close()
			return l.Addr().(*net.TCPAddr).Port, nil
		}
	}
	return
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func randomBytes() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}
