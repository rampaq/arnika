package peer

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/arnika-project/arnika/config"
	h "github.com/arnika-project/arnika/internal/test_helpers"
	m "github.com/arnika-project/arnika/internal/test_mocks"
	"github.com/arnika-project/arnika/kms"
)

// TODO: proper testing of the actual Wireguard code either in container or via mocking the netlink and wireguard drivers

// Test client sendRequestAndSetPSK
// <- KMS not available, fallback key not available
// -> deactivate vpn peer
// -> returns KMSError
func TestClient_KmsErr_NoFallbackKey(t *testing.T) {
	tests := []struct {
		name    string
		kmsMode config.KmsMode
	}{
		{"KmsStrict", config.KmsStrict},
		{"KmsFallback_NoFallbackKey", config.KmsLastFallback},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{KMSMode: tt.kmsMode}
			vpn := new(m.MockVPN)
			keystore := m.NewKeyStore("error", nil)
			client := initiator{cfg, vpn, keystore}
			vpn.SetKey(&kms.Key{ID: "", Key: "testkey"})
			err := client.sendRequestAndSetPSK()

			if err == nil {
				t.Fatal("expected non-nil error")
			}
			if !errors.As(err, &KMSError{}) {
				t.Fatal("expected KMS error")
			}
			if vpn.Activated {
				t.Fatal("tunnel still active")
			}
		})
	}
}

// Test client sendRequestAndSetPSK
// <- KMS not available, fallback key available
// <- KmsFallback mode
// <- peer connection error
// -> set fallback key for vpn
// -> returns error
func TestClient_KmsErr_HasKmsFallback_PeerConnErr(t *testing.T) {
	key := kms.Key{
		ID:  "bcbff446-c81b-4167-b40a-7c88f253ebda",
		Key: "q7eo2gEaZ48U/dI8qCFuLy5q0ySnkQGDJzCCZQQkfJg=",
	}
	cfg := &config.Config{KMSMode: config.KmsLastFallback}
	vpn := new(m.MockVPN)
	keystore := m.NewKeyStore("fallback-only", []kms.Key{key})
	client := initiator{cfg, vpn, keystore}
	vpn.SetKey(&kms.Key{ID: "", Key: "testkey"})
	vpn.DeactivatePeer()
	err := client.sendRequestAndSetPSK()

	if err == nil {
		t.Fatal("expected non-nil error")
	}
	assertActiveKey(t, vpn, key)
}

// Test client sendRequestAndSetPSK
// <- KMS available
// <- KmsFallback, KmsStrict mode
// <- peer connection ok
// -> set key for vpn
// -> no error
// and ---
// <- KMS not available, fallback key available
// <- KmsFallback mode
// <- peer connection ok
// -> set fallback key for vpn
// -> no error
func TestClientServer_PeerConnOk(t *testing.T) {
	key := kms.Key{
		ID:  "bcbff446-c81b-4167-b40a-7c88f253ebda",
		Key: "q7eo2gEaZ48U/dI8qCFuLy5q0ySnkQGDJzCCZQQkfJg=",
	}

	tests := []struct {
		name     string
		kmsMode  config.KmsMode
		keyStore kms.KeyStore
	}{
		{
			"KmsStrict_KmsOk",
			config.KmsStrict,
			m.NewKeyStoreDB([]kms.Key{key}),
		},
		{
			"KmsFallback_KmsOk",
			config.KmsLastFallback,
			m.NewKeyStoreDB([]kms.Key{key}),
		},
		{
			"KmsFallback_KmsErr_HasFallback",
			config.KmsLastFallback,
			m.NewKeyStore("fallback-only", []kms.Key{key}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpn := new(m.MockVPN)
			vpn.SetKey(&kms.Key{ID: "", Key: "testkey"})
			vpn.DeactivatePeer()

			listenAddr := h.GetFreeLocalhostAddr()
			// listen, err := net.Listen("tcp", listenAddr)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			lc := net.ListenConfig{}
			lc.Listen(ctx, "tcp", listenAddr)
			// intintionally not accept, it should not matter if peer is listening or not
			// 100 ms timeout should kick in

			cfg := &config.Config{KMSMode: tt.kmsMode, ServerAddress: listenAddr}
			client := initiator{cfg, vpn, tt.keyStore}
			err := client.sendRequestAndSetPSK()
			if err != nil {
				t.Errorf("expected no error, got %v", err)
			}
			assertActiveKey(t, vpn, key)
		})
	}
}

// Test client sendRequestAndSetPSK
// <- KMS available
// <- KmsFallback modes
// <- connection to peer fails
// -> correctly sets key from KMS
// func TestClient_KmsOk_PeerConnErr(t *testing.T) {
// 	key := kms.Key{
// 		ID:  "bcbff446-c81b-4167-b40a-7c88f253ebda",
// 		Key: "q7eo2gEaZ48U/dI8qCFuLy5q0ySnkQGDJzCCZQQkfJg=",
// 	}
// 	tests := []struct {
// 		name    string
// 		kmsMode config.KmsMode
// 	}{
// 		{"KmsStrict", config.KmsStrict},
// 		{"KmsFallback", config.KmsLastFallback},
// 	}
//
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			cfg := &config.Config{KMSMode: tt.kmsMode}
// 			vpn := new(m.MockVPN)
// 			keystore := m.NewKeyStoreDB([]kms.Key{key})
// 			client := initiator{cfg, vpn, keystore}
// 			vpn.SetKey("testkey")
// 			vpn.DeactivatePeer()
// 			err := client.sendRequestAndSetPSK()
// 			if err != nil {
// 				t.Fatalf("expected no error, got %v", err)
// 			}
// 			assertActiveKey(t, vpn, key)
// 		})
// 	}
// }

func TestClient_KeyUsageLimit(t *testing.T) {
	usageLimit := 5
	vpn := m.NewMockVPNLimited(usageLimit)
	key := kms.Key{
		ID:  "bcbff446-c81b-4167-b40a-7c88f253ebda",
		Key: "q7eo2gEaZ48U/dI8qCFuLy5q0ySnkQGDJzCCZQQkfJg=",
	}
	// cfg := &config.Config{KMSMode: config.KmsLastFallback}
	// keystore := m.NewKeyStore("fallback-only", []kms.Key{key})
	// client := initiator{cfg, vpn, keystore}
	for i := range usageLimit - 1 {
		err := vpn.SetKey(&key)
		if err != nil {
			t.Fatalf("failed on usage %d/%d", i, usageLimit)
		}
	}
	err := vpn.SetKey(&key)
	if err == nil {
		t.Fatal("did not fail with stale key")
	}
	assertActiveKey(t, vpn, key)
}

func assertActiveKey(t *testing.T, vpn *m.MockVPN, key kms.Key) {
	t.Helper()
	if !vpn.Activated {
		t.Error("tunnel not active")
	}
	if vpn.Key != key.Key {
		t.Errorf("tunnel key invalid. Expected: %s, got: %s", key.Key, vpn.Key)
	}
}
