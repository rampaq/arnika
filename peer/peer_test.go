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

type MockKeyStore struct {
	CurrentKey kms.Key
	Activated  bool
	mode       string
}

func (s *MockKeyStore) getNewRandomKey() (*kms.Key, error) {
	kid, err := uuid.NewRandom()
	check(err)
	rnd, err := randomBytes()
	check(err)
	s.CurrentKey = kms.Key{ID: kid.String(), Key: rnd}
	return &s.CurrentKey, nil
}

func (s *MockKeyStore) GetNewKey() (*kms.Key, error) {
	switch s.mode {
	case "error":
		return nil, fmt.Errorf("intentional error in kms.GetNewKey")
	case "random":
		return s.getNewRandomKey()
	default:
		return &s.CurrentKey, nil
	}
}

func (s *MockKeyStore) GetKeyByID(keyID string) (*kms.Key, error) {
	if s.CurrentKey.ID != keyID {
		return nil, fmt.Errorf("no key with this ID")
	}
	return &s.CurrentKey, nil
}

func (s *MockKeyStore) GetFallbackKey() (*kms.Key, error) {
	if s.CurrentKey == (kms.Key{}) {
		return nil, fmt.Errorf("no previous key")
	}
	return &s.CurrentKey, nil
}

// Test that Server correctly exits when context is cancelled
func TestServerExitsContextCancel(t *testing.T) {
	// port, err := getFreePort()
	// check(err)
	// addr := "localhost:" + strconv.Itoa(port)
	cfg := &config.Config{ListenAddress: "localhost:0"}
	vpn := new(MockVPN)
	keystore := &MockKeyStore{}
	server := NewServer(cfg, vpn, keystore)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Millisecond)
	defer cancel()
	finished := make(chan struct{})
	go func() {
		skipPush := make(chan bool)
		server.Start(ctx, skipPush)
		finished <- struct{}{}
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
	client := NewClient(cfg, vpn, keystore)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Millisecond)
	defer cancel()
	finished := make(chan struct{})
	go func() {
		skipPush := make(chan bool)
		client.Start(ctx, skipPush)
		finished <- struct{}{}
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
	keystore := &MockKeyStore{CurrentKey: key}

	vpnServer := new(MockVPN)
	vpnClient := new(MockVPN)
	server := NewServer(cfg, vpnServer, keystore)
	client := NewClient(cfg, vpnClient, keystore)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup

	// server
	wg.Add(1)
	go func() {
		skipPush := make(chan bool)
		server.Start(ctx, skipPush)
		wg.Done()
	}()

	// client
	wg.Add(1)
	go func() {
		skipPush := make(chan bool)
		client.Start(ctx, skipPush)
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
