package kdf

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
)

// Uncomment to generate some random data and run with go test ./kdf -v
func TestGenKeys(t *testing.T) {
	fmt.Println("Input, key type, result:")

	// generate master pqc key
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Errorf("Error generating random bytes: %v", err)
	}
	b64key := base64.StdEncoding.EncodeToString(key)

	for _, keyType := range []PqcSubkeyType{
		SubkeyPqcOnly,
		SubkeyPqcHybrid,
		SubkeyPqcAuth,
	} {
		out, err := GetPQCSubkey(b64key, keyType)
		if err != nil {
			t.Error("error pqc subkey")
		}
		var keyTypeStr string
		switch keyType {
		case SubkeyPqcOnly:
			keyTypeStr = "SubkeyPqcOnly"
		case SubkeyPqcHybrid:
			keyTypeStr = "SubkeyPqcHybrid"
		case SubkeyPqcAuth:
			keyTypeStr = "SubkeyPqcAuth"
		}
		fmt.Printf("{\"%s\", %-15s, \"%s\"},\n", b64key, keyTypeStr, out)
	}

	// generate kms key
	key2 := make([]byte, 32)
	_, err = rand.Read(key2)
	if err != nil {
		t.Errorf("Error generating random bytes %v:", err)
	}
	b64key2 := base64.StdEncoding.EncodeToString(key2)
	hybridKey, err := GetHybridKey(b64key2, b64key)
	if err != nil {
		t.Errorf("hybrid key err: %v", err)
	}
	fmt.Println("Hybrid key:", "kmsKey, pqcKey, result")
	fmt.Printf("{\"%s\", \"%s\", \"%s\"},\n", b64key2, b64key, hybridKey)
}

func TestSubkeys(t *testing.T) {
	tests := []struct {
		pqcKey  string
		keyType PqcSubkeyType
		want    string
	}{
		{"mvWINzdBZXTZhtVFrSouqcSRVy1NO5isHPnYH5j3WOs=", SubkeyPqcOnly, "Eg4nkVGeWgLvLgg8ZY6sxtEgucqfnBaFQmRg/5cEQOk="},
		{"mvWINzdBZXTZhtVFrSouqcSRVy1NO5isHPnYH5j3WOs=", SubkeyPqcHybrid, "/uhVFdO6TSx3ICcOSIvOFLbW8kwW9Y94tzlHnXDJNgA="},
		{"mvWINzdBZXTZhtVFrSouqcSRVy1NO5isHPnYH5j3WOs=", SubkeyPqcAuth, "M3iZvGihbMUa7lSp3nPO01gBEdRsFRNPTyu4sOQcw5Q="},
		{"fKBkAYUcQgJq2MI9bJgYLJDd7caUAWD7La2ijtTJ/Rg=", SubkeyPqcOnly, "EROOP/QQGCQ3gnW7o7OEusz4hfl4+x1ihOTGno70v1U="},
		{"fKBkAYUcQgJq2MI9bJgYLJDd7caUAWD7La2ijtTJ/Rg=", SubkeyPqcHybrid, "xU0x5mBrbk7swRnhsR3+DdHzSb2UR0jaAam6LO/MKwo="},
		{"fKBkAYUcQgJq2MI9bJgYLJDd7caUAWD7La2ijtTJ/Rg=", SubkeyPqcAuth, "/rdY1j9EJFKDWCxSRX+1r3CC7FOFzX2ZqEXx85QOCh0="},
	}

	set := map[string]bool{}
	for _, tt := range tests {
		// checks that subkeys are not the same
		if _, exists := set[tt.want]; exists {
			t.Errorf("some subkeys are the same: %s", tt.want)
		}
		set[tt.want] = true

		// t.Run enables running "subtests", one for each
		// table entry. These are shown separately
		// when executing `go test -v`.
		testname := fmt.Sprintf("%s,%d->%s", tt.pqcKey, tt.keyType, tt.want)
		t.Run(testname, func(t *testing.T) {
			ans, err := GetPQCSubkey(tt.pqcKey, tt.keyType)
			if err != nil {
				t.Errorf("got error during deriving subkey: %v", err)
			}
			if ans != tt.want {
				t.Errorf("got %s, want %s", ans, tt.want)
			}
		})
	}
}

func TestHybridKey(t *testing.T) {
	tests := []struct {
		kmsKey string
		pqcKey string
		want   string
	}{
		{"p1ZcPXbYbV/CmVteyBrLOd7JwQom/nOGVAcmKe7TMEo=", "mvWINzdBZXTZhtVFrSouqcSRVy1NO5isHPnYH5j3WOs=", "fKIju6H6QKKVm04gHnJPd/1EerLCE6Jo1gpeBmaGtyo="},
		{"t3qiz04ysf6mV2VmYTIdUyVWuUKbemOiX8D2WCb/KI8=", "iuAIgJpt7EiKkoGIQXlXlTdoHaYLTiIP5OXgJUWOR1k=", "H+Oq/zEi+8i7pt+pJ+jfP3Ge+mXur0nFOHe+259JY8E="},
	}

	set := map[string]bool{}
	for _, tt := range tests {
		// checks that results are not the same
		if _, exists := set[tt.want]; exists {
			t.Errorf("some hybrid keys are the same: %s", tt.want)
		}
		set[tt.want] = true

		// t.Run enables running "subtests", one for each
		// table entry. These are shown separately
		// when executing `go test -v`.
		testname := fmt.Sprintf("%s,%s->%s", tt.kmsKey, tt.pqcKey, tt.want)
		t.Run(testname, func(t *testing.T) {
			ans, err := GetHybridKey(tt.kmsKey, tt.pqcKey)
			if err != nil {
				t.Errorf("got error during deriving subkey: %v", err)
			}
			if ans != tt.want {
				t.Errorf("got %s, want %s", ans, tt.want)
			}
		})
	}
}
