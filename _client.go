package main

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	username         = "foo"
	password         = ssh.Password("bar")
	serverAddrString = "localhost:2200"
	localAddrString  = "localhost:8000"
	remoteAddrString = "localhost:9999"
)

type forwardedTCPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

type clientPassword string

func (password clientPassword) Password(user string) (string, error) {
	return string(password), nil
}

func forward(localConn net.Conn) {
	remote, err := net.Dial("tcp", ":8000")
	if err != nil {
		fmt.Println(err)
		return
	}

	go func() {
		_, err = io.Copy(remote, localConn)
		if err != nil {
			fmt.Println("remote: io.Copy failed: %v", err)
		}
	}()

	// Copy sshConn.Reader to localConn.Writer
	go func() {
		_, err = io.Copy(localConn, remote)
		if err != nil {
			fmt.Println("localConn: io.Copy failed: %v", err)
		}
	}()
}

func testSsh() {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{password},
	}

	sshClientConn, err := ssh.Dial("tcp", serverAddrString, config)
	if err != nil {
		fmt.Println("ssh.Dial failed: %s", err)
		return
	}

	sshConn, err := sshClientConn.Listen("tcp", remoteAddrString)
	if err != nil {
		fmt.Println(err)
		return
	}

	for {
		conn, err := sshConn.Accept()
		if err != nil {
			return
		}

		fmt.Println(conn.RemoteAddr())

		fmt.Println("new connection")

		local, err := net.Dial("tcp", ":8000")
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("tcp:8000")

		close := func() {
			conn.Close()
			local.Close()
		}
		go copyConnections(conn, local, close)
	}
}

func copyConnections(a, b io.ReadWriter, close func()) {
	var once sync.Once
	go func() {
		io.Copy(a, b)
		once.Do(close)
	}()
	go func() {
		io.Copy(b, a)
		once.Do(close)
	}()
}

func main() {
	for {
		testSsh()
		time.Sleep(1 * time.Second)
	}
}
