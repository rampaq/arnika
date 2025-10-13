package net

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arnika-project/arnika/config"
)

type helperArgs struct {
	cfg     *config.Config
	request string
	result  *ArnikaServerRequest
}
type helperArgsClientServer struct {
	cfgClient    *config.Config
	cfgServer    *config.Config
	clientReq    ArnikaServerRequest
	serverExpect *ArnikaServerRequest
}

// handler should block indefinitely when no result reader is present
// func TestHandlerBlocksWhenNoReader(t *testing.T) {
// 	client, server := net.Pipe()
// 	result := make(chan ArnikaServerRequest)
// 	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Millisecond)
// 	defer cancel()
//
// 	signal := make(chan bool)
// 	go func() {
// 		// result is never read from, blocks indefinitely even if context is cancelled
// 		handleServerConnection(ctx, nil, server, result)
// 		cancel()
// 		<-signal
// 	}()
// 	client.Write([]byte("kms a4346dfd-1d63-4aee-9560-02536014f1c2\n"))
// 	<-ctx.Done()
// 	select {
// 	case <-signal:
// 		t.Log("handler finished")
// 	case <-time.After(100 * time.Millisecond):
// 		t.Errorf("handler does not respect context")
// 	}
// }

// handler should respect context cancel when no data is sent through connection
func TestHandlerExitsOnTimeoutConnectionHang(t *testing.T) {
	_, server := net.Pipe()
	result := make(chan ArnikaServerRequest)
	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Millisecond)
	defer cancel()

	signal := make(chan bool)
	go func() {
		handleServerConnection(ctx, nil, server, result)
		cancel()
		signal <- true
	}()
	// client.Write([]byte("kms a4346dfd-1d63-4aee-9560-02536014f1c2\n"))

	<-ctx.Done()
	select {
	case <-signal:
		t.Log("handler finished")
	case <-time.After(100 * time.Millisecond):
		t.Errorf("handler does not respect context")
	}
}

func TestArnikaServerHandlerPQCFallback(t *testing.T) {
	// want=nil means that nothing is sent on result channel to main
	pqcKey := "pdf1z+oy/1CUtGMzPJjFFsqGzGcNg/sDn8iD7GUQwxI="
	t.Log(pqcKey)
	tests := []struct {
		request string
		want    *ArnikaServerRequest
	}{
		// valid kms <key-id> request
		{"kms a4346dfd-1d63-4aee-9560-02536014f1c2", &ArnikaServerRequest{"a4346dfd-1d63-4aee-9560-02536014f1c2", true}},
		// invalid message
		{"nil a4346dfd-1d63-4aee-9560-02536014f1c2", nil},
		// valid pqc <nonce-tag> request with valid pqcKey
		{"pqc BfQVcwCv7iba4TkO20jUP2lX2+SwgnQ5/55P4lDW8CSl2JUwJp5a17b3+txtKP+3GOZPplTo8dlXi9tiuiIyBg==", &ArnikaServerRequest{"", false}},
		// invalid nonce-tag
		{"pqc abcdef012456", nil},
	}

	for _, tt := range tests {
		testname := fmt.Sprintf("%s,%v", tt.request, tt.want)
		t.Run(testname, func(t *testing.T) {
			tmpf := filepath.Join(t.TempDir(), "pqc.psk")
			err := os.WriteFile(tmpf, []byte(pqcKey), 0o600)
			check(err)
			err = helperExpectServer(t, helperArgs{
				cfg: &config.Config{
					KMSMode:    config.KmsPQCFallback,
					PQCPSKFile: tmpf,
				},
				request: tt.request,
				result:  tt.want,
			})
			if err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}

func TestArnikaClientRequest(t *testing.T) {
	// want=nil means that nothing is sent on result channel to main
	pqcKey := "pdf1z+oy/1CUtGMzPJjFFsqGzGcNg/sDn8iD7GUQwxI="
	pqcKey2 := "fC4GW0C88VSzcUTwRkssxHLhokwH4J494vZYcD17aC0="
	t.Log(pqcKey)
	tests := []struct {
		pqcKeyClient  *string
		requestStruct ArnikaServerRequest
		pqcKeyServer  *string
		// nil means no valid response received
		responseWant  *ArnikaServerRequest
	}{
		// valid kms <key-id> request
		{nil, ArnikaServerRequest{"a4346dfd-1d63-4aee-9560-02536014f1c2", true}, nil, &ArnikaServerRequest{"a4346dfd-1d63-4aee-9560-02536014f1c2", true}},
		// valid kms <key-id> request with PqcFallback
		{&pqcKey, ArnikaServerRequest{"a4346dfd-1d63-4aee-9560-02536014f1c2", true}, &pqcKey, &ArnikaServerRequest{"a4346dfd-1d63-4aee-9560-02536014f1c2", true}},
		// valid kms <key-id> request with PqcFallback, different keys
		{&pqcKey, ArnikaServerRequest{"a4346dfd-1d63-4aee-9560-02536014f1c2", true}, &pqcKey2, &ArnikaServerRequest{"a4346dfd-1d63-4aee-9560-02536014f1c2", true}},

		// mismatch between present key-id and bool flag
		{nil, ArnikaServerRequest{"a4346dfd-1d63-4aee-9560-02536014f1c2", false}, nil, nil},

		// pqc fallback request with matching pqcKey
		{&pqcKey, ArnikaServerRequest{"", false}, &pqcKey, &ArnikaServerRequest{"", false}},
		// pqc fallback, mismatch between client and server keys
		{&pqcKey, ArnikaServerRequest{"", false}, &pqcKey2, nil},
		// pqc fallaback request to server with strict mode
		{&pqcKey, ArnikaServerRequest{"", false}, nil, nil},
		// pqc fallback request from client without pqc fallback enabled errors
		{nil, ArnikaServerRequest{"", false}, nil, nil},
		// pqc fallback request from client without pqc fallback enabled errors
		{nil, ArnikaServerRequest{"", false}, &pqcKey, nil},
	}

	for _, tt := range tests {
		testname := fmt.Sprintf("%v,%v,%v,%v", tt.pqcKeyClient, tt.requestStruct, tt.pqcKeyServer, tt.responseWant)
		t.Run(testname, func(t *testing.T) {
			tmpdir := t.TempDir()
			tmpfClient := filepath.Join(tmpdir, "pqc-client.psk")
			tmpfServer := filepath.Join(tmpdir, "pqc-server.psk")
			if tt.pqcKeyClient != nil {
				err := os.WriteFile(tmpfClient, []byte(*tt.pqcKeyClient), 0o600)
				check(err)
			}
			if tt.pqcKeyServer != nil {
				err := os.WriteFile(tmpfServer, []byte(*tt.pqcKeyServer), 0o600)
				check(err)
			}
			err := helperExpectClientServer(t, helperArgsClientServer{
				cfgClient: &config.Config{
					KMSMode:    getPQCMode(tt.pqcKeyClient),
					PQCPSKFile: tmpfClient,
				},
				cfgServer: &config.Config{
					KMSMode:    getPQCMode(tt.pqcKeyServer),
					PQCPSKFile: tmpfServer,
				},
				clientReq:    tt.requestStruct,
				serverExpect: tt.responseWant,
			})
			if err != nil {
				t.Errorf("test failed: %v", err)
			}
		})
	}
}

func getPQCMode(key *string) config.KmsMode {
	if key == nil {
		return config.KmsStrict
	}
	return config.KmsPQCFallback
}

func randomBytes(n int) string {
	key := make([]byte, n)
	_, err := rand.Read(key)
	check(err)
	b64 := base64.StdEncoding.EncodeToString(key)
	return b64
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func helperExpectClientServer(t *testing.T, args helperArgsClientServer) error {
	tcpRequest, err := createTCPRequest(args.cfgClient, args.clientReq)
	if err != nil {
		if args.serverExpect == nil {
			// if request is not send and no valid message is expected on server, this means test passed
			return nil
		}
		return err
	}

	// create bidirectional connection
	client, server := net.Pipe()
	result := make(chan ArnikaServerRequest)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	go func() {
		handleServerConnection(ctx, args.cfgServer, server, result)
		cancel()
	}()
	client.Write(tcpRequest)

	return checkServerResult(t, ctx, args.serverExpect, result)
}

func helperExpectServer(t *testing.T, args helperArgs) error {
	// create bidirectional connection
	client, server := net.Pipe()
	result := make(chan ArnikaServerRequest)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	go func() {
		handleServerConnection(ctx, args.cfg, server, result)
		cancel()
	}()
	client.Write([]byte(args.request + "\n"))

	return checkServerResult(t, ctx, args.result, result)
}

func checkServerResult(t *testing.T, ctx context.Context, expectedResult *ArnikaServerRequest, result chan ArnikaServerRequest) error {
	select {
	case r := <-result:
		if expectedResult == nil {
			return fmt.Errorf("did not expect any valid request, got: %+v", r)
		}
		if r != *expectedResult {
			return fmt.Errorf("expected %v, got %+v", *expectedResult, r)
		}

	case <-ctx.Done():
		err := ctx.Err()
		switch err {
		case context.Canceled:
			// handler finished on its own
			if expectedResult != nil {
				return fmt.Errorf("no valid request received, expected: %+v", *expectedResult)
			}
		case context.DeadlineExceeded:
			t.Errorf("server did not respond in 100 ms")
			return err
		default:
			t.Errorf("unknown context err: %v", err)
			return err
		}
	}
	return nil
}
