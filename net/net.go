package net

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/arnika-project/arnika/config"
	"github.com/google/uuid"
)

const (
	MaxLineLenBytes = 1024
)

type ArnikaRequest interface {
	ToBytes() ([]byte, error)
}

// RequestKMSKeyID notifies peer to use KMS key with KeyID
type RequestKMSKeyID struct {
	KeyID string
}

func (r RequestKMSKeyID) ToBytes() ([]byte, error) {
	if r.KeyID == "" {
		return nil, fmt.Errorf("no value for KeyID specified")
	}
	return []byte("KMS " + r.KeyID), nil
}

// RequestKMSFallback notifies peer to use last valid KMS key
type RequestKMSFallback struct{}

func (r RequestKMSFallback) ToBytes() ([]byte, error) {
	return []byte("KMS-FALLBACK-LAST"), nil
}

func UnmarshalRequest(s string) (ArnikaRequest, error) {
	cmd, rest, found := strings.Cut(s, " ")
	if !found {
		switch s {
		case "KMS-FALLBACK-LAST":
			return RequestKMSFallback{}, nil
		}
		return nil, fmt.Errorf("invalid msg format")
	}
	switch cmd {
	case "KMS":
		keyID := rest
		if keyID == "" || uuid.Validate(keyID) != nil {
			return nil, fmt.Errorf("invalid KeyID given")
		}
		return RequestKMSKeyID{KeyID: keyID}, nil
	default:
		return nil, fmt.Errorf("unknown command")
	}
}

type NetServer struct {
	cfg              *config.Config
	result           chan<- ArnikaRequest
	readWriteTimeout time.Duration
	wg               sync.WaitGroup
}

// NewServer creates new server with default timeout of 15 seconds
func NewServer(cfg *config.Config, result chan<- ArnikaRequest) *NetServer {
	return &NetServer{
		cfg:              cfg,
		result:           result,
		readWriteTimeout: 15 * time.Second,
	}
}

// WithTimeout sets custom timeout for read & write socket operations; modifies original and returns it
func (s *NetServer) WithTimeout(readWriteTimeout time.Duration) *NetServer {
	s.readWriteTimeout = readWriteTimeout
	return s
}

// Start a TCP server which listens for connecations and sends the parsed requests in `result` channel
func (s *NetServer) Start(ctx context.Context) {
	listen, err := net.Listen("tcp", s.cfg.ListenAddress)
	if err != nil {
		log.Panicln(err.Error())
	}
	log.Printf("TCP Server listening on %s\n", s.cfg.ListenAddress)
	defer func() {
		// wait until all handlers are done to clean up
		s.wg.Wait()
		log.Println("TCP Server shutdown")
		err = listen.Close()
		if err != nil {
			log.Println(err.Error())
		}
		close(s.result)
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				// listen.Close() causes Accept to return with error
				c, err := listen.Accept()
				if err != nil {
					log.Println(err.Error())
					break
				}
				go s.handleServerConnection(ctx, c)
			}
		}
	}()

	<-ctx.Done()
}

// handleServerConnection closes connection c when done
// timeout of ReadWriteTimeout for network read/write
// no timeout for result channel
func (s *NetServer) handleServerConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	s.wg.Add(1)
	defer s.wg.Done()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// time out in one minute if no data is received.
	// the error can be safely ignored.
	_ = conn.SetReadDeadline(time.Now().Add(s.readWriteTimeout))

	lim := &io.LimitedReader{
		R: conn,
		N: MaxLineLenBytes,
	}
	scanner := bufio.NewScanner(lim)

	msgChan := make(chan string)
	go func() {
		// read a single line only
		if !scanner.Scan() {
			if errRead := scanner.Err(); errRead != nil {
				fmt.Printf("Failed to read from connection: %v\n", errRead)
				cancel()
				return
			}
		}
		msgChan <- scanner.Text()
	}()

	select {
	case msg := <-msgChan:
		req, err := UnmarshalRequest(msg)
		if err != nil {
			log.Printf("Error during parsing request: %v\n", err)
			return
		}
		s.result <- req
		_, err = conn.Write([]byte("ACK" + "\n"))
		if err != nil {
			log.Println("Failed to write to connection:", err)
		}
		// for multiline messages:
		// reset number of remaining bytes in LimitReader
		// lim.N = MaxLineLenBytes
		// reset the read deadline
		// _ = conn.SetReadDeadline(time.Now().Add(ReadWriteTimeout))

	case <-ctx.Done():
		err := ctx.Err()
		log.Println("Connection handler closed:", err)
	}
}

// NetClient sends a key request to peer's TCP server
func NetClient(cfg *config.Config, req ArnikaRequest) error {
	reqBytes, err := req.ToBytes()
	if err != nil {
		return fmt.Errorf("error during serialization: %w", err)
	}
	c, err := net.DialTimeout("tcp", cfg.ServerAddress, time.Second)
	if err != nil {
		return err
	}
	defer func() {
		c.Close()
	}()

	err = c.SetDeadline(time.Now().Add(time.Millisecond * 100))
	if err != nil {
		return fmt.Errorf("could not set conn timeout: %w", err)
	}

	reqBytes = append(reqBytes, '\n')
	_, err = c.Write(reqBytes)
	return err
}
