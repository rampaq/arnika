package net

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/crypto/auth"
	"github.com/arnika-project/arnika/crypto/kdf"
)

type ArnikaServerRequest struct {
	KeyID        string
	KMSAvailable bool
}

func (req *ArnikaServerRequest) Marshal() (string, error) {
	if req.KMSAvailable && req.KeyID == "" {
		return "", fmt.Errorf("invalid request")
	}
	if req.KMSAvailable {
		return "kms " + req.KeyID, nil
	} else {
		return "pqc", nil
	}
}

func ArnikaServer(ctx context.Context, cfg *config.Config, result chan<- ArnikaServerRequest) {
	// ctx, cancel := context.WithCancel(ctx)
	log.Printf("TCP Server listening on %s\n", cfg.ListenAddress)
	ln, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		log.Panicln(err.Error())
		return
	}
	defer func() {
		log.Println("TCP Server shutdown")
		err = ln.Close()
		if err != nil {
			log.Println(err.Error())
		}
		close(result)
	}()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				log.Println(err.Error())
				continue
			}
			// prevent request handling taking too long
			// exception: when no result reader is present, handleServerConnection blocks indifinitely
			ctxTimeout, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
			handleServerConnection(ctx, cfg, c, result)
			<-ctxTimeout.Done() // accept new connections every 100 ms, no more, no less
			cancel()            // we are always waiting for timeout by design, this will make typechecker happy
		}
	}()

	<-ctx.Done()
}

func ArnikaClient(cfg *config.Config, req ArnikaServerRequest) error {
	tcpReq, err := createTCPRequest(cfg, req)
	if err != nil {
		return err
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
	_, err = c.Write(tcpReq)
	if err != nil {
		return err
	}
	return c.SetDeadline(time.Now().Add(time.Millisecond * 100))
}

func createTCPRequest(cfg *config.Config, req ArnikaServerRequest) ([]byte, error) {
	var resp string
	switch {
	case req.KMSAvailable:
		resp_, err := req.Marshal()
		if err != nil {
			return nil, err
		}
		resp = resp_

	case !req.KMSAvailable && cfg.KMSMode == config.KmsPQCFallback:
		pqcKey, err := kdf.GetPQCMasterKey(cfg.PQCPSKFile)
		if err != nil {
			return nil, err
		}
		authentication, err := auth.New(pqcKey)
		if err != nil {
			return nil, err
		}
		marshal, err := req.Marshal()
		if err != nil {
			return nil, err
		}
		nonceTag, err := authentication.GetTag(marshal)
		if err != nil {
			return nil, err
		}
		resp = marshal + " " + nonceTag

	default:
		return nil, fmt.Errorf("unclear intent")
	}

	return []byte(resp + "\n"), nil
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

func handleServerConnection(ctx context.Context, cfg *config.Config, c net.Conn, result chan<- ArnikaServerRequest) {
	if c == nil {
		panic("received nil connection")
	}
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered from panic:", r)
		}
		if c != nil {
			c.Close()
		}
	}()

	scanner := bufio.NewScanner(c)
	if scanner == nil {
		panic("received nil scanner")
	}

	msgChan := make(chan string)
	errChan := make(chan error)
	go func() {
		// read a single line only
		if !scanner.Scan() {
			if errRead := scanner.Err(); errRead != nil {
				errChan <- errRead
				return
			}
		}
		msgChan <- scanner.Text()
	}()

	select {
	case errRead := <-errChan:
		fmt.Printf("Failed to read from connection: %v", errRead)

	case msg := <-msgChan:
		req, err := parseRequest(cfg, msg)
		if err != nil {
			fmt.Printf("error during parsing request: %v\n", err)
			return
		}
		result <- *req
		_, err = c.Write([]byte("ACK" + "\n"))
		if err != nil { // Handle the write error
			fmt.Println("Failed to write to connection:", err)
		}

	case <-ctx.Done():
		err := ctx.Err()
		fmt.Println("Connection handler closed:", err)
	}
}
