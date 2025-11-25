package test_helpers

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"strconv"
)

func Check(err error) {
	if err != nil {
		panic(err)
	}
}

func GetFreeLocalhostAddr() string {
	port, err := getFreePort()
	Check(err)
	return "localhost:" + strconv.Itoa(port)
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

func RandomBytes() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}
