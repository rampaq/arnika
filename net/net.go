package net

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/arnika-project/arnika/config"
	"github.com/google/uuid"
)

type ArnikaServerRequest interface {
	ToBytes() ([]byte, error)
}

// ReqestKMSKeyID notifies peer to use KMS key with KeyID
type ReqestKMSKeyID struct {
	KeyID string
}

func (r ReqestKMSKeyID) ToBytes() ([]byte, error) {
	if r.KeyID == "" {
		return nil, fmt.Errorf("no value for KeyID specified")
	}
	return []byte("kms " + r.KeyID), nil
}

// RequestKMSLast notifies peer to use last valid KMS key
type RequestKMSLast struct{}

func (r RequestKMSLast) ToBytes() ([]byte, error) {
	return []byte("kms-use-last"), nil
}

func UnmarshalRequest(s string) (ArnikaServerRequest, error) {
	switch {
	case strings.HasPrefix(s, "kms "):
		keyID := s[4:]
		if keyID == "" || uuid.Validate(keyID) != nil {
			return nil, fmt.Errorf("invalid KeyID given")
		}
		return ReqestKMSKeyID{KeyID: keyID}, nil
	case s == "kms-use-last":
		return RequestKMSLast{}, nil
	default:
		return nil, fmt.Errorf("unknown format")
	}
}

// ArnikaServer starts a TCP server which runs handleServerConnection on the TCP message and sends the result in `result` channel
func ArnikaServer(url string, result chan ArnikaServerRequest, done chan bool) {
	// defer close(done)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit,
		syscall.SIGTERM,
		syscall.SIGINT,
	)
	go func() {
		<-quit
		log.Println("TCP Server shutdown")
		close(done)
		close(result)
	}()
	log.Printf("TCP Server listening on %s\n", url)
	ln, err := net.Listen("tcp", url)
	if err != nil {
		log.Panicln(err.Error())
		return
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				log.Println(err.Error())
				break
			}
			go handleServerConnection(c, result)
			time.Sleep(100 * time.Millisecond)
		}
	}()
	<-done
	err = ln.Close()
	if err != nil {
		log.Println(err.Error())
	}
}

// ArnikaClient sends a key request to peer's TCP server
func ArnikaClient(cfg *config.Config, req ArnikaServerRequest) error {
	reqBytes, err := req.ToBytes()
	if err != nil {
		return fmt.Errorf("error during serialization: %w", err)
	}
	c, err := net.DialTimeout("tcp", cfg.ServerAddress, time.Millisecond*100)
	if err != nil {
		return err
	}
	defer func() {
		if c != nil {
			c.Close()
		}
	}()

	reqBytes = append(reqBytes, []byte("\n")...)
	_, err = c.Write(reqBytes)
	if err != nil {
		return err
	}
	return c.SetDeadline(time.Now().Add(time.Millisecond * 100))
}

func handleServerConnection(c net.Conn, result chan ArnikaServerRequest) {
	// Check that c is not nil.
	if c == nil {
		panic("received nil connection")
	}
	defer func() {
		if r := recover(); r != nil {
			log.Println("Recovered from panic:", r)
		}
	}()
	for {
		// scan message
		scanner := bufio.NewScanner(c)
		// Check that scanner is not nil.
		if scanner == nil {
			panic("received nil scanner")
		}

	loopScan:
		for scanner.Scan() {
			msg := scanner.Text()
			r, err := UnmarshalRequest(msg)
			if err != nil {
				log.Println("Failed to parse request:", err)
				break loopScan
			}
			result <- r

			_, err = c.Write([]byte("ACK" + "\n"))
			if err != nil { // Handle the write error
				log.Println("Failed to write to connection:", err)
				break loopScan
			}
		}
		if errRead := scanner.Err(); errRead != nil { // Handle the read error
			if errRead == io.EOF { // Handle EOF
				log.Println("Connection closed by remote host.")
				break
			}
			// expected
			// fmt.Println("Failed to read from connection:", errRead)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
