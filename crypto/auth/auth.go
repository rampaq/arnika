package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"slices"

	nacl "golang.org/x/crypto/nacl/auth"

	"github.com/arnika-project/arnika/crypto/kdf"
)

type auth struct {
	key [32]byte
}

// New creates an authentication scheme with specified key
// Use raw b64-encoded PQC key, an authentication subkey is subsequently derived from this key
func New(pqcKey string) (*auth, error) {
	authKey, err := kdf.GetPQCSubkey(pqcKey, kdf.SubkeyPqcAuth)
	if err != nil {
		return nil, fmt.Errorf("could not obtain auth subkey: %w", err)
	}

	key, err := base64.StdEncoding.DecodeString(authKey)
	if err != nil {
		return nil, err
	}
	return &auth{
		key: ([32]byte)(key),
	}, nil
}

// Create a random 32-byte nonce and compute 32 byte HMAC tag of (nonce||msg) with given key.
// Output 64 bytes of (nonce||tag) encoded in base64.
func (auth *auth) GetTag(msg string) (string, error) {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", fmt.Errorf("error generating nonce: %w", err)
	}

	fullMsg := slices.Concat(nonce, []byte(msg))
	tag := nacl.Sum(fullMsg, &auth.key)
	nonceTag := slices.Concat(nonce, tag[:])

	nonceTagStr := base64.StdEncoding.EncodeToString(nonceTag)
	return nonceTagStr, nil
}

// Verify message with given nonce||tag.
func (auth *auth) VerifyNonceTag(msg string, nonceTag string) bool {
	nonceTagRaw, err := base64.StdEncoding.DecodeString(nonceTag)
	if err != nil {
		return false
	}
	if len(nonceTagRaw) != 64 {
		return false
	}

	nonce := nonceTagRaw[:32]
	tag := nonceTagRaw[32:64]
	fullMsg := slices.Concat(nonce, []byte(msg))

	// fmt.Printf("ver: nonce: %d %x | tag: %d %x\n", len(nonce), nonce, len(tag), tag)
	// fmt.Printf("ver: fmsg: %x | nonce: %d %x | tag: %d %x\n", fullMsg, len(nonce), nonce, len(tag), tag)
	return nacl.Verify(
		tag,
		fullMsg,
		&auth.key,
	)
}
