package kdf

import (
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

type PqcSubkeyType int8

const (
	// used to combine PQC + KMS
	SubkeyPqcHybrid PqcSubkeyType = iota
	// standalone PQC
	SubkeyPqcOnly
	// used for arnika server message authentication
	SubkeyPqcAuth
)

// GetHybridKey combines PQC and KMS keys using HKDF.
// KMS key is in b64 format, PQC key is the raw b64 OSK obtained from Rosenpass.
// Internally, this function obtains the PQC hybrid subkey, hence you should pass the raw Rosenpass OSK.
func GetHybridKey(kmsKey, pqcKey string) (string, error) {
	domain := []byte("arnika hybrid-key")

	key1, err := base64.StdEncoding.DecodeString(kmsKey)
	if err != nil {
		return "", fmt.Errorf("error decoding base64 string: %w", err)
	}

	pqcSubKey, err := GetPQCSubkey(pqcKey, SubkeyPqcHybrid)
	if err != nil {
		return "", fmt.Errorf("error deriving pqc subkey: %w", err)
	}
	key2, err := base64.StdEncoding.DecodeString(pqcSubKey)
	if err != nil {
		return "", fmt.Errorf("error decoding base64 string: %w", err)
	}

	// Create a new HKDF instance with SHA3-256 as the hash function with domain separation
	hkdf := hkdf.New(sha3.New256, append(key1, key2...), nil, domain)

	// Generate a derived key using HKDF
	derivedKey := make([]byte, 32) // Output key length
	if _, err := io.ReadFull(hkdf, derivedKey); err != nil {
		return "", fmt.Errorf("error generating derived key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(derivedKey), nil
}

// GetPQCSubkey obtains subkeys from Rosenpass' OSK (in b64 format).
// This is done so that the keys used in different scenarios are as independent as possible.
// pqcKey is the Rosenpass' OSK read from exchanged password file
func GetPQCSubkey(pqcKey string, keyType PqcSubkeyType) (string, error) {
	var domain []byte

	switch keyType {
	case SubkeyPqcHybrid:
		domain = []byte("arnika pqc-kms")
	case SubkeyPqcOnly:
		domain = []byte("arnika pqc-only")
	case SubkeyPqcAuth:
		domain = []byte("arnika pqc-auth")
	default:
		return "", fmt.Errorf("invalid subkey type: %d", keyType)
	}

	key, err := base64.StdEncoding.DecodeString(pqcKey)
	if err != nil {
		return "", fmt.Errorf("error decoding base64 string: %w", err)
	}

	hkdf := hkdf.New(sha3.New256, key, nil, domain)
	derivedKey := make([]byte, 32) // Output key length
	if _, err := io.ReadFull(hkdf, derivedKey); err != nil {
		return "", fmt.Errorf("error generating derived key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(derivedKey), nil
}
