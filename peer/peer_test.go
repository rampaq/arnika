package peer

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/arnika-project/arnika/config"
	h "github.com/arnika-project/arnika/internal/test_helpers"
	m "github.com/arnika-project/arnika/internal/test_mocks"
	"github.com/arnika-project/arnika/kms"
	anet "github.com/arnika-project/arnika/net"
)

// Test that Server correctly exits when context is cancelled
func TestServerExitsContextCancel(t *testing.T) {
	cfg := &config.Config{ListenAddress: "localhost:0"}
	vpn := new(m.MockVPN)
	keystore := m.NewKeyStore("error", nil)
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
	vpn := new(m.MockVPN)
	keystore := m.NewKeyStore("error", nil)
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
	addr := h.GetFreeLocalhostAddr()

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
	keystore := m.NewKeyStoreDB([]kms.Key{key})

	vpnServer := new(m.MockVPN)
	vpnClient := new(m.MockVPN)
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
	addrA, addrB := h.GetFreeLocalhostAddr(), h.GetFreeLocalhostAddr()

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
	keystoreA := m.NewKeyStoreDB([]kms.Key{key1, key2})
	vpnA := &m.MockVPN{Pubkey: pubkeyA}
	peerA, err := NewPeer(cfgA, vpnA, keystoreA)
	h.Check(err)

	// B
	keystoreB := m.NewKeyStoreDB([]kms.Key{key2, key1})
	vpnB := &m.MockVPN{Pubkey: pubkeyB}
	peerB, err := NewPeer(cfgB, vpnB, keystoreB)
	h.Check(err)

	assertFinalVpnKeysMatch(t, peerA, peerB, vpnA, vpnB)
}

// Test that setting master/slave statically in config works
func TestPeersNegotiateSamePSKConfigMasterSlave(t *testing.T) {
	addrA := h.GetFreeLocalhostAddr()

	pubkeyA, pubkeyB := "PHIHZhhgchOvxcqAw2uploHg2TiYxDHi97gojn82da0=", "1vbc1wm220ajhUbroI9bI1/Bt+fkleRQcDMxApfq+Dc="
	cfgA := &config.Config{
		ListenAddress:          addrA,
		KMSMode:                config.KmsStrict,
		Interval:               time.Millisecond, // repeat handshake every millisecond
		WireguardPeerPublicKey: pubkeyB,
		PQCPSKFile:             "",
	}
	cfgB := &config.Config{
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
	keystoreA := m.NewKeyStoreDB([]kms.Key{key1, key2})
	vpnA := &m.MockVPN{Pubkey: pubkeyA}
	peerA, err := NewPeer(cfgA, vpnA, keystoreA)
	h.Check(err)

	// B
	keystoreB := m.NewKeyStoreDB([]kms.Key{key2, key1})
	vpnB := &m.MockVPN{Pubkey: pubkeyB}
	peerB, err := NewPeer(cfgB, vpnB, keystoreB)
	h.Check(err)

	assertFinalVpnKeysMatch(t, peerA, peerB, vpnA, vpnB)
}

// Test that negotiation works for Fallback mode when KMS connection is ok
func TestPeersNegotiateSamePSKFallbackKMSOnline(t *testing.T) {
	addrA, addrB := h.GetFreeLocalhostAddr(), h.GetFreeLocalhostAddr()

	pubkeyA, pubkeyB := "PHIHZhhgchOvxcqAw2uploHg2TiYxDHi97gojn82da0=", "1vbc1wm220ajhUbroI9bI1/Bt+fkleRQcDMxApfq+Dc="
	cfgA := &config.Config{
		ListenAddress:          addrA,
		ServerAddress:          addrB,
		KMSMode:                config.KmsLastFallback,
		Interval:               time.Millisecond, // repeat handshake every millisecond
		WireguardPeerPublicKey: pubkeyB,
		PQCPSKFile:             "",
	}
	cfgB := &config.Config{
		ListenAddress:          addrB,
		ServerAddress:          addrA,
		KMSMode:                config.KmsLastFallback,
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
	keystoreA := m.NewKeyStoreDB([]kms.Key{key1, key2})
	vpnA := &m.MockVPN{Pubkey: pubkeyA}
	peerA, err := NewPeer(cfgA, vpnA, keystoreA)
	h.Check(err)

	// B
	keystoreB := m.NewKeyStoreDB([]kms.Key{key2, key1})
	vpnB := &m.MockVPN{Pubkey: pubkeyB}
	peerB, err := NewPeer(cfgB, vpnB, keystoreB)
	h.Check(err)

	assertFinalVpnKeysMatch(t, peerA, peerB, vpnA, vpnB)
}

// Test that negotiation works for Fallback mode when KMS connection is down
func TestPeersNegotiateSamePSKFallbackKMSOffline(t *testing.T) {
	addrA, addrB := h.GetFreeLocalhostAddr(), h.GetFreeLocalhostAddr()

	pubkeyA, pubkeyB := "PHIHZhhgchOvxcqAw2uploHg2TiYxDHi97gojn82da0=", "1vbc1wm220ajhUbroI9bI1/Bt+fkleRQcDMxApfq+Dc="
	cfgA := &config.Config{
		ListenAddress:          addrA,
		ServerAddress:          addrB,
		KMSMode:                config.KmsLastFallback,
		Interval:               time.Millisecond, // repeat handshake every millisecond
		WireguardPeerPublicKey: pubkeyB,
		PQCPSKFile:             "",
	}
	cfgB := &config.Config{
		ListenAddress:          addrB,
		ServerAddress:          addrA,
		KMSMode:                config.KmsLastFallback,
		Interval:               time.Millisecond,
		WireguardPeerPublicKey: pubkeyA,
		PQCPSKFile:             "",
	}

	key := kms.Key{
		ID:  "bcbff446-c81b-4167-b40a-7c88f253ebda",
		Key: "q7eo2gEaZ48U/dI8qCFuLy5q0ySnkQGDJzCCZQQkfJg=",
	}
	// A
	keystoreA := m.NewKeyStore("fallback-only", []kms.Key{key})
	vpnA := &m.MockVPN{Pubkey: pubkeyA}
	peerA, err := NewPeer(cfgA, vpnA, keystoreA)
	h.Check(err)

	// B
	keystoreB := m.NewKeyStore("fallback-only", []kms.Key{key})
	vpnB := &m.MockVPN{Pubkey: pubkeyB}
	peerB, err := NewPeer(cfgB, vpnB, keystoreB)
	h.Check(err)

	assertFinalVpnKeysMatch(t, peerA, peerB, vpnA, vpnB)
}

func TestErrorOnReceiveFallbackForStrictMode(t *testing.T) {
	addr := h.GetFreeLocalhostAddr()
	pubkey := "PHIHZhhgchOvxcqAw2uploHg2TiYxDHi97gojn82da0="
	cfgA := &config.Config{
		ListenAddress: addr,
		KMSMode:       config.KmsStrict,
		PQCPSKFile:    "",
	}

	// A
	keystoreA := m.NewKeyStore("error", nil)
	vpnA := &m.MockVPN{Pubkey: pubkey}
	peerA, err := NewPeer(cfgA, vpnA, keystoreA)
	h.Check(err)

	err = peerA.r.processRequest(anet.RequestKMSFallback{})
	if err == nil {
		t.Error("expected error when received fallback request and using KmsStrict mode")
	}
}

// run both peers for 10 milliseconds and check that final VPN keys of both peers match
func assertFinalVpnKeysMatch(t *testing.T, peerA, peerB *arnikaPeer, vpnA, vpnB *m.MockVPN) {
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
			t.Fatalf("peer key mismatch: peerA set %s, peer B set %s", vpnA.Key, vpnB.Key)
		}
	case <-time.After(2 * time.Millisecond):
		t.Fatalf("server & client did not finish in time")
	}
}
