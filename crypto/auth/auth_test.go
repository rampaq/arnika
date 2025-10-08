package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"testing"
)

// Uncomment to generate some random data and run with go test ./kdf -v
func TestGenTags(t *testing.T) {
	// generate master key
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Errorf("Error generating random bytes: %v", err)
	}
	b64key := base64.StdEncoding.EncodeToString(key)

	fmt.Println("Input, key type, result:")
	for _, msg := range []string{
		"message",
		"pqc",
		"stčšě23$",
	} {
		auth, err := New(b64key)
		if err != nil {
			t.Errorf("cannot create auth: %v", err)
		}
		nonceTag, err := auth.GetTag(msg)
		if err != nil {
			t.Errorf("cannot generate tag: %v", err)
		}
		if !auth.VerifyNonceTag(msg, nonceTag) {
			t.Error("could not verify tag")
		}
		fmt.Printf("{\"%s\", \"%s\", \"%s\"},\n", b64key, msg, nonceTag)
	}
}

func TestVerifyPreviouslyGenerated(t *testing.T) {
	tests := []struct {
		key        string
		msg        string
		nonceTag   string
		wantVerify bool
	}{
		// valid
		{"pdf1z+oy/1CUtGMzPJjFFsqGzGcNg/sDn8iD7GUQwxI=", "message", "VLW4ShT9Szf944xxJK4nn1o9bo2iu5vI6/qn4NMBRG/jRxOSAEEf0O71qr3zv2De/vmLzKARTgLkyDqoVpwzoQ==", true},
		// invalid tag
		{"pdf1z+oy/1CUtGMzPJjFFsqGzGcNg/sDn8iD7GUQwxI=", "message", "dmFsaWQgYjY0", false},
		// invalid tag, 64 raw bytes
		{"pdf1z+oy/1CUtGMzPJjFFsqGzGcNg/sDn8iD7GUQwxI=", "message", "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ==", false},
		// invalid B64 encoding
		{"pdf1z+oy/1CUtGMzPJjFFsqGzGcNg/sDn8iD7GUQwxI=", "message", "INVALIDB64$f944xxJK4nn1o9bo2iu5vI6/qn4NMBRG/jRxOSAEEf0O71qr3zv2De/vmLzKARTgLkyDqoVpwzoQ==", false},
		// forged message
		{"pdf1z+oy/1CUtGMzPJjFFsqGzGcNg/sDn8iD7GUQwxI=", "messa", "VLW4ShT9Szf944xxJK4nn1o9bo2iu5vI6/qn4NMBRG/jRxOSAEEf0O71qr3zv2De/vmLzKARTgLkyDqoVpwzoQ==", false},
		// correct tag
		{"pdf1z+oy/1CUtGMzPJjFFsqGzGcNg/sDn8iD7GUQwxI=", "pqc", "BfQVcwCv7iba4TkO20jUP2lX2+SwgnQ5/55P4lDW8CSl2JUwJp5a17b3+txtKP+3GOZPplTo8dlXi9tiuiIyBg==", true},
		// forged message
		{"pdf1z+oy/1CUtGMzPJjFFsqGzGcNg/sDn8iD7GUQwxI=", "pqc\x86", "BfQVcwCv7iba4TkO20jUP2lX2+SwgnQ5/55P4lDW8CSl2JUwJp5a17b3+txtKP+3GOZPplTo8dlXi9tiuiIyBg==", false},
		// valid
		{"pdf1z+oy/1CUtGMzPJjFFsqGzGcNg/sDn8iD7GUQwxI=", "stčšě23$", "C2kWrxxmZZXGu8XG4Wu/yhC+SyknwH1SrEqHpSMdyJRGziLmC9nV619FMd+XFX+xd5rGOc+7mDRrZULQTiTWZQ==", true},
		// forged message
		{"pdf1z+oy/1CUtGMzPJjFFsqGzGcNg/sDn8iD7GUQwxI=", "st$daswe8", "C2kWrxxmZZXGu8XG4Wu/yhC+SyknwH1SrEqHpSMdyJRGziLmC9nV619FMd+XFX+xd5rGOc+7mDRrZULQTiTWZQ==", false},
		{"fC4GW0C88VSzcUTwRkssxHLhokwH4J494vZYcD17aC0=", "message", "bYqbmbPq9Srr1seT2phfsYaX4K8WvfPUJba+exUcwhysLyf298LIO7c/HwuAOFKyHQ6LmNmDIqfeQcmCc0ljOg==", true},
		{"fC4GW0C88VSzcUTwRkssxHLhokwH4J494vZYcD17aC0=", "pqc", "YmjUJ+KIVZqhJvwYdqvLXwM8iELtMhmdjNfYhRL75nmoU0YlDnjkAhdNDpTzl+ro3sfEGrZwcxKDBGMe9tSFpQ==", true},
		{"fC4GW0C88VSzcUTwRkssxHLhokwH4J494vZYcD17aC0=", "stčšě23$", "e5Mgh0o1QxgqhRMx58XaWi/oEefzdQwNApjSd6D/dwjQxw+hyzoH2fdQI9gzMk6JoXGGEIpXnGo71xbNaGG6SA==", true},
	}

	for _, tt := range tests {
		// t.Run enables running "subtests", one for each
		// table entry. These are shown separately
		// when executing `go test -v`.
		testname := fmt.Sprintf("key:%s,msg:%s,tag:%s,verify:%s", tt.key, tt.msg, tt.nonceTag, strconv.FormatBool(tt.wantVerify))
		t.Run(testname, func(t *testing.T) {
			auth, err := New(tt.key)
			if err != nil {
				t.Errorf("cannot create auth: %v", err)
			}
			if auth.VerifyNonceTag(tt.msg, tt.nonceTag) != tt.wantVerify {
				t.Errorf("verify mismatch: expected %s, got %s", strconv.FormatBool(tt.wantVerify), strconv.FormatBool(!tt.wantVerify))
			}
		})
	}
}
