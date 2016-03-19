package main

import (
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	username   = "smarthome"
	localPort  = ":80"
	serverAddr = "localhost:22022"
	remoteAddr = "localhost:5001"
)

func SSHAgent() ssh.AuthMethod {
	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		return ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers)
	}
	return nil
}

func forward() {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{SSHAgent()},
	}

	sshClientConn, err := ssh.Dial("tcp", serverAddr, config)
	if err != nil {
		log.Fatal("ssh.Dial failed:", err)
		return
	}

	sshConn, err := sshClientConn.Listen("tcp", remoteAddr)
	if err != nil {
		log.Fatal(err)
		return
	}

	for {
		conn, err := sshConn.Accept()
		if err != nil {
			return
		}

		local, err := net.Dial("tcp", localPort)
		if err != nil {
			log.Fatal(err)
			return
		}

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
		forward()
		time.Sleep(1 * time.Second)
	}
}
