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
	"github.com/arnika-project/arnika/crypto/auth"
	"github.com/arnika-project/arnika/crypto/kdf"
)

type ArnikaServerRequest struct {
	KeyID        string
	KMSAvailable bool
}

func (req *ArnikaServerRequest) Marshal() string {
	if req.KMSAvailable {
		return "kms " + req.KeyID
	} else {
		return "pqc"
	}
}


func ArnikaServer(cfg *config.Config, result chan ArnikaServerRequest, done chan bool) {
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
	log.Printf("TCP Server listening on %s\n", cfg.ListenAddress)
	ln, err := net.Listen("tcp", cfg.ListenAddress)
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
			go handleServerConnection(cfg, c, result)
			time.Sleep(100 * time.Millisecond)
		}
	}()
	<-done
	err = ln.Close()
	if err != nil {
		log.Println(err.Error())
	}
}

func ArnikaClient(cfg *config.Config, req ArnikaServerRequest) error {
	if req.KMSAvailable && req.KeyID == "" {
		return fmt.Errorf("KeyID is empty")
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

	var resp string
	if !req.KMSAvailable && cfg.KMSMode == config.KmsPQCFallback {
		pqcKey, err := kdf.GetPQCMasterKey(cfg.PQCPSKFile)
		if err != nil {
			return err
		}
		authentication, err := auth.New(pqcKey)
		if err != nil {
			return err
		}
		nonceTag, err := authentication.GetTag("pqc")
		if err != nil {
			return err
		}
		resp = req.Marshal() + " " + nonceTag
	} else {
		resp = req.Marshal()
	}

	_, err = c.Write([]byte(resp + "\n"))
	if err != nil {
		return err
	}
	return c.SetDeadline(time.Now().Add(time.Millisecond * 100))
}

func parseRequest(cfg *config.Config, msg string) (*ArnikaServerRequest, error) {
	switch {
	case strings.HasPrefix(msg, "pqc "):
		nonceTag := msg[4:]
		pqcKey, err := kdf.GetPQCMasterKey(cfg.PQCPSKFile)
		if err != nil {
			return nil, err
		}
		authentication, err := auth.New(pqcKey)
		if err != nil {
			return nil, err
		}
		if !authentication.VerifyNonceTag("pqc", nonceTag) {
			return nil, fmt.Errorf("forged PQC-fallback message")
		}
		return &ArnikaServerRequest{KMSAvailable: false, KeyID: ""}, nil

	case strings.HasPrefix(msg, "kms "):
		keyID := msg[4:]
		if keyID == "" {
			return nil, fmt.Errorf("invalid KeyID")
		}
		return &ArnikaServerRequest{KMSAvailable: true, KeyID: keyID}, nil

	default:
		return nil, fmt.Errorf("unknown format")
	}
}

func handleServerConnection(cfg *config.Config, c net.Conn, result chan ArnikaServerRequest) {
	// Check that c is not nil.
	if c == nil {
		panic("received nil connection")
	}
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered from panic:", r)
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

			req, err := parseRequest(cfg, msg)
			if err != nil {
				fmt.Printf("error during parsing request: %v\n", err)
				break loopScan
			}
			result <- *req

			_, err = c.Write([]byte("ACK" + "\n"))
			if err != nil { // Handle the write error
				fmt.Println("Failed to write to connection:", err)
				break loopScan
			}
		}
		if errRead := scanner.Err(); errRead != nil { // Handle the read error
			if errRead == io.EOF { // Handle EOF
				fmt.Println("Connection closed by remote host.")
				break
			}
			// expected
			// fmt.Println("Failed to read from connection:", errRead)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
