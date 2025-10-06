package net

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/arnika-project/arnika/config"
	"github.com/google/uuid"
)

type ArnikaServerRequest struct {
	KeyID string
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
	if req.KeyID == "" {
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

	_, err = c.Write([]byte(req.KeyID + "\n"))
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
			if msg == "" || uuid.Validate(msg) != nil {
				log.Println("received invalid key_id UUID, aborting")
				break loopScan
			}
			result <- ArnikaServerRequest{KeyID: msg}

			_, err := c.Write([]byte("ACK" + "\n"))
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
