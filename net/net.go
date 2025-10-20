package net

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
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

type ArnikaServer struct {
	cfg              *config.Config
	result           chan<- ArnikaRequest
	readWriteTimeout time.Duration
}

// NewServer creates new server with default timeout of 15 seconds
func NewServer(cfg *config.Config, result chan<- ArnikaRequest) *ArnikaServer {
	return &ArnikaServer{
		cfg:              cfg,
		result:           result,
		readWriteTimeout: 15 * time.Second,
	}
}

// SetTimeout sets custom timeout for read & write socket operations; modifies original and returns it
func (s *ArnikaServer) WithTimeout(readWriteTimeout time.Duration) *ArnikaServer {
	s.readWriteTimeout = readWriteTimeout
	return s
}

// Start a TCP server which listens for connecations and sends the parsed requests in `result` channel
func (s *ArnikaServer) Start(ctx context.Context) {
	listen, err := net.Listen("tcp", s.cfg.ListenAddress)
	if err != nil {
		log.Panicln(err.Error())
	}
	log.Printf("TCP Server listening on %s\n", s.cfg.ListenAddress)
	defer func() {
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
					continue
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
func (s *ArnikaServer) handleServerConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

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

// ArnikaClient sends a key request to peer's TCP server
func ArnikaClient(cfg *config.Config, req ArnikaRequest) error {
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

	reqBytes = append(reqBytes, '\n')
	_, err = c.Write(reqBytes)
	if err != nil {
		return err
	}
	return c.SetDeadline(time.Now().Add(time.Millisecond * 100))
}

