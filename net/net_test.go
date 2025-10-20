package net

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/arnika-project/arnika/config"
)

type helperArgs struct {
	request string
	result  ArnikaRequest
}
type helperArgsClientServer struct {
	clientReq    ArnikaRequest
	serverExpect ArnikaRequest
}

// handler should respect context cancel when no data is sent through connection
func TestHandlerExitsOnTimeoutConnectionHang(t *testing.T) {
	_, connServer := net.Pipe()
	result := make(chan ArnikaRequest)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Millisecond)
	defer cancel()

	server := NewServer(&config.Config{ListenAddress: ""}, result).WithTimeout(2 * time.Millisecond)

	handlerFinished := make(chan bool)
	go func() {
		server.handleServerConnection(context.Background(), connServer)
		cancel() // early finish, do not block <-ctx.Done()
		handlerFinished <- true
	}()

	<-ctx.Done()
	select {
	case <-handlerFinished:
		t.Log("handler finished")
	case <-time.After(5 * time.Millisecond):
		t.Errorf("handler did not finish in time")
	}
}

// handler should respect context cancel when no data is sent through connection
func TestServerStartsAndRespectsContextCancel(t *testing.T) {
	result := make(chan ArnikaRequest)
	finished := make(chan struct{})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Millisecond)
	defer cancel()

	server := NewServer(&config.Config{ListenAddress: "localhost:0"}, result)
	// start server
	go func() {
		server.Start(ctx)
		finished <- struct{}{}
	}()

	// wait for timeout
	<-ctx.Done()
	select {
	case <-finished:
	case <-time.After(5 * time.Millisecond):
		t.Errorf("handler did not finish in time")
	}
}

func TestArnikaServerHandlerVariousRequests(t *testing.T) {
	// want=nil means that nothing is sent on result channel to main
	tests := []struct {
		request string
		want    ArnikaRequest
	}{
		// valid kms <key-id> request
		{"KMS a4346dfd-1d63-4aee-9560-02536014f1c2", RequestKMSKeyID{"a4346dfd-1d63-4aee-9560-02536014f1c2"}},
		// invalid <key-id> (not UUID)
		{"KMS xxx", nil},
		// invalid
		{"KMS ", nil},
		{"nil a4346dfd-1d63-4aee-9560-02536014f1c2", nil},
		{"unknown", nil},
	}

	for _, tt := range tests {
		testname := fmt.Sprintf("%s,%v", tt.request, tt.want)
		t.Run(testname, func(t *testing.T) {
			err := helperExpectServer(t, helperArgs{
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
	tests := []struct {
		requestStruct ArnikaRequest
		responseWant  ArnikaRequest
	}{
		{RequestKMSKeyID{"a4346dfd-1d63-4aee-9560-02536014f1c2"}, RequestKMSKeyID{"a4346dfd-1d63-4aee-9560-02536014f1c2"}},
		{RequestKMSKeyID{"49a04cdd-0885-4877-9b75-ec172a3cef81"}, RequestKMSKeyID{"49a04cdd-0885-4877-9b75-ec172a3cef81"}},
		{RequestKMSKeyID{"6dd5b479-7d48-453d-8e44-da85cd900783"}, RequestKMSKeyID{"6dd5b479-7d48-453d-8e44-da85cd900783"}},
		// KeyID cannot be ""
		{RequestKMSKeyID{""}, nil},
		{RequestKMSFallback{}, RequestKMSFallback{}},
	}

	port, err := getFreePort()
	check(err)
	addr := "localhost:" + strconv.Itoa(port)
	cfg := &config.Config{ListenAddress: addr, ServerAddress: addr}
	result := make(chan ArnikaRequest)
	server := NewServer(cfg, result)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// start server
	go server.Start(ctx)

	// pass tests to running server
	for _, tt := range tests {
		testname := fmt.Sprintf("%v,%v", tt.requestStruct, tt.responseWant)
		t.Run(testname, func(t *testing.T) {
			err := ArnikaClient(cfg, tt.requestStruct)
			if err != nil {
				// could not send -> no response will be received -> test passed
				if tt.responseWant != nil {
					t.Errorf("client failed: %v", err)
					return
				}
			}
			select {
			case r := <-result:
				if r != tt.responseWant {
					t.Errorf("expected %#v, got %#v", tt.responseWant, r)
				}
			case <-time.After(5 * time.Millisecond):
				if tt.responseWant != nil {
					// responseWant=nil means we did not expect a response; test passed
					t.Errorf("no result received in 5 milliseconds")
				}
			}
		})
	}
}

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

func helperExpectClientServer(t *testing.T, args helperArgsClientServer) error {
	tcpRequest, err := args.clientReq.ToBytes()
	if err != nil {
		if args.serverExpect == nil {
			// if request is not send and no valid message is expected on server, this means test passed
			return nil
		}
		return err
	}

	// create bidirectional connection
	clientConn, serverConn := net.Pipe()
	result := make(chan ArnikaRequest)
	server := NewServer(nil, result).WithTimeout(2 * time.Millisecond)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()

	go func() {
		server.handleServerConnection(ctx, serverConn)
		cancel()
	}()
	clientConn.Write(tcpRequest)
	return checkServerResult(t, ctx, args.serverExpect, result)
}

func helperExpectServer(t *testing.T, args helperArgs) error {
	// create bidirectional connection
	clientConn, serverConn := net.Pipe()
	result := make(chan ArnikaRequest)
	server := NewServer(nil, result).WithTimeout(2 * time.Millisecond)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()

	go func() {
		server.handleServerConnection(ctx, serverConn)
		cancel()
	}()
	clientConn.Write([]byte(args.request + "\n"))
	return checkServerResult(t, ctx, args.result, result)
}

func checkServerResult(t *testing.T, ctx context.Context, expectedResult ArnikaRequest, result chan ArnikaRequest) error {
	select {
	case r := <-result:
		if expectedResult == nil {
			return fmt.Errorf("did not expect any valid request, got: %v", r)
		}
		if r != expectedResult {
			return fmt.Errorf("expected %#v, got %#v", expectedResult, r)
		}

	case <-ctx.Done():
		err := ctx.Err()
		switch err {
		case context.Canceled:
			// handler finished on its own
			if expectedResult != nil {
				return fmt.Errorf("no valid request received, expected: %#v", expectedResult)
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

func check(err error) {
	if err != nil {
		panic(err)
	}
}
