package test_mocks

import (
	"fmt"

	"github.com/arnika-project/arnika/kms"
	"github.com/google/uuid"
	h "github.com/arnika-project/arnika/internal/test_helpers"
)

type MockVPN struct {
	Key       string
	Activated bool
	Pubkey    string
}
type mockKeyStore struct {
	keys []kms.Key
	mode string
}

/// VPN
func (vpn *MockVPN) SetKey(s string) error {
	vpn.Key = s
	vpn.Activated = true
	return nil
}

func (vpn *MockVPN) DeactivatePeer() error {
	vpn.Activated = false
	return nil
}

func (vpn *MockVPN) GetPublicKey() (string, error) {
	if vpn.Pubkey == "" {
		return "", fmt.Errorf("pubkey not set")
	}
	return vpn.Pubkey, nil
}

/// KeyStore
// func NewEmptyMockKeyStore() kms.KeyStore {
// 	return &mockKeyStore{mode: "error"}
// }

func NewKeyStoreDB(keys []kms.Key) kms.KeyStore {
	return NewKeyStore("fix", keys)
}

func NewKeyStore(mode string, keys []kms.Key) kms.KeyStore {
	switch mode {
	case "error", "random":
		if len(keys) != 0 {
			panic(fmt.Errorf("supplied keys are ignored in this mode"))
		}
	case "fallback-only":
		if len(keys) != 1 {
			panic(fmt.Errorf("expected exactly one fallback key"))
		}
	case "fix", "fixed":
		if len(keys) == 0 {
			panic( fmt.Errorf("expected some keys"))
		}
	default:
		panic(fmt.Errorf("unknown mode"))
	}
	return &mockKeyStore{mode: mode, keys: keys}
}

func (s *mockKeyStore) GetNewKey() (*kms.Key, error) {
	switch s.mode {
	case "error", "fallback-only":
		return nil, fmt.Errorf("intentional error in kms.GetNewKey")
	case "random":
		return s.getNewRandomKey()
	default:
		return &s.keys[0], nil
	}
}

func (s *mockKeyStore) GetKeyByID(keyID string) (*kms.Key, error) {
	for _, key := range s.keys {
		if key.GetID() == keyID {
			return &key, nil
		}
	}
	return nil, fmt.Errorf("no key with this ID")
}

func (s *mockKeyStore) GetFallbackKey() (*kms.Key, error) {
	if len(s.keys) == 0 {
		return nil, fmt.Errorf("no previous key")
	}
	return &s.keys[0], nil
}

func (s *mockKeyStore) getNewRandomKey() (*kms.Key, error) {
	kid, err := uuid.NewRandom()
	h.Check(err)
	kidStr := kid.String()
	rnd, err := h.RandomBytes()
	h.Check(err)
	key := kms.Key{ID: kidStr, Key: rnd}
	s.keys = append(s.keys, key)
	return &key, nil
}
