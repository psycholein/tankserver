package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"sync"

	"golang.org/x/crypto/ssh"
)

type forwardedTCPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

type tcpipforwardPayload struct {
	Addr string
	Port uint32
}

func main() {
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "foo" && string(pass) == "bar" {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

	privateBytes, err := ioutil.ReadFile("id_rsa")
	if err != nil {
		log.Fatal("Failed to load private key (./id_rsa)")
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	config.AddHostKey(private)

	listener, err := net.Listen("tcp", "0.0.0.0:2200")
	if err != nil {
		log.Fatalf("Failed to listen on 2200 (%s)", err)
	}

	log.Print("Listening on 2200...")
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection (%s)", err)
			continue
		}
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
		if err != nil {
			log.Printf("Failed to handshake (%s)", err)
			continue
		}

		log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

		go handleRegs(reqs, sshConn)
		go handleChannels(chans)
	}
}

func handleRegs(reqs <-chan *ssh.Request, sshConn *ssh.ServerConn) {
	for req := range reqs {
		var payload tcpipforwardPayload
		if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
			fmt.Println("ERROR", err)
			continue
		}

		addr := fmt.Sprintf("%s:%d", payload.Addr, payload.Port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			fmt.Println("Unable to listen on address: ", addr)
			req.Reply(false, nil)
			continue
		}

		reply := (payload.Port == 0) && req.WantReply
		if !reply {
			req.Reply(true, nil)
		} else {
			req.Reply(false, nil)
		}
		go func() {
			fmt.Println("Listening on address: ", ln.Addr().String())
			quit := make(chan bool)

			go func() {
				for {
					select {
					case <-quit:
						return
					default:
						conn, err := ln.Accept()
						if err != nil {
							continue
						}
						go func(conn net.Conn) {
							p := forwardedTCPPayload{}
							var err error
							var portnum int

							p.Addr = payload.Addr
							p.Port = payload.Port
							p.OriginAddr, portnum, err = getHostPortFromAddr(conn.RemoteAddr())
							if err != nil {
								return
							}

							p.OriginPort = uint32(portnum)
							ch, reqs, err := sshConn.OpenChannel("forwarded-tcpip", ssh.Marshal(p))
							if err != nil {
								log.Println("Open forwarded Channel: ", err.Error())
								return
							}

							go ssh.DiscardRequests(reqs)
							go func(ch ssh.Channel, conn net.Conn) {
								close := func() {
									ch.Close()
									conn.Close()
								}
								go copyConnections(conn, ch, close)
							}(ch, conn)
						}(conn)
					}
				}
			}()
			sshConn.Wait()
			fmt.Println("Stop forwarding/listening on ", ln.Addr())
			ln.Close()
			quit <- true
		}()
	}
}

func getHostPortFromAddr(addr net.Addr) (host string, port int, err error) {
	host, portString, err := net.SplitHostPort(addr.String())
	if err != nil {
		return
	}
	port, err = strconv.Atoi(portString)
	return
}

func handleChannels(chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		newChannel.Reject(ssh.UnknownChannelType, "not allowed")
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
