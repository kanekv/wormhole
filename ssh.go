package main

import (
	"code.google.com/p/go.crypto/ssh"
	"code.google.com/p/go.crypto/ssh/terminal"
	"fmt"
	"github.com/kelseyhightower/envconfig"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
)

type configuration struct {
	PrivateKeyPath       string
	LocalSSHAddr         string
	RemoteSSHAddr        string
	RemoteForwardAddress string
	RemoteSSHUser        string
	RemotePrivateKeyPath string
}

var appConfig configuration

func main() {
	println("starting ssh server...")
	err := envconfig.Process("wormhole", &appConfig)
	if err != nil {
		log.Fatal(err.Error())
	}

	if appConfig.LocalSSHAddr == "" || appConfig.PrivateKeyPath == "" ||
		appConfig.RemoteSSHAddr == "" || appConfig.RemoteForwardAddress == "" ||
		appConfig.RemoteSSHUser == "" || appConfig.RemotePrivateKeyPath == "" {
		fmt.Println("Missing config")
		os.Exit(-1)
	}

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in
			// a production setting.
			if c.User() == "testuser" && string(pass) == "" {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

	privateBytes, err := ioutil.ReadFile(appConfig.PrivateKeyPath)
	if err != nil {
		panic("Failed to load private key")
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		panic("Failed to parse private key")
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", appConfig.LocalSSHAddr)
	if err != nil {
		panic("failed to listen for connection")
	}

	for {
		nConn, err := listener.Accept()
		if err != nil {
			panic("failed to accept incoming connection")
		}

		conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
		if err != nil {
			panic("failed to handshake")
		}

		go processRequests(conn, reqs)
		for newChannel := range chans {
			if newChannel.ChannelType() != "session" {
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}
			channel, requests, err := newChannel.Accept()
			if err != nil {
				panic("could not accept channel.")
			}

			go func(in <-chan *ssh.Request) {
				for req := range in {
					ok := false
					switch req.Type {
					case "shell":
						ok = true
						if len(req.Payload) > 0 {
							ok = false
						}
					}
					req.Reply(ok, nil)
				}
			}(requests)

			term := terminal.NewTerminal(channel, "> ")

			go func() {
				defer channel.Close()
				for {
					_, err := term.ReadLine()
					if err != nil {
						break
					}
				}
			}()
		}
	}
}

func processRequests(conn *ssh.ServerConn, reqs <-chan *ssh.Request) {
	for req := range reqs {
		if req.Type != "tcpip-forward" {
			// accept only tcpip-forward requests
			if req.WantReply {
				req.Reply(false, nil)
			}
			continue
		}
		type channelForwardMsg struct {
			Laddr string
			Lport uint32
		}
		m := &channelForwardMsg{}
		ssh.Unmarshal(req.Payload, m)

		privateBytes, err := ioutil.ReadFile(appConfig.RemotePrivateKeyPath)
		if err != nil {
			log.Fatal(err.Error())
		}

		signer, err := ssh.ParsePrivateKey(privateBytes)
		if err != nil {
			log.Fatal(err.Error())
		}

		config := &ssh.ClientConfig{
			User: appConfig.RemoteSSHUser,
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(signer),
			},
		}
		sshClientConn, err := ssh.Dial("tcp", appConfig.RemoteSSHAddr, config)
		if err != nil {
			log.Fatal(err.Error())
		}

		type channelOpenForwardMsg struct {
			raddr string
			rport uint32
			laddr string
			lport uint32
		}

		fm := &channelOpenForwardMsg{
			raddr: "localhost",
			rport: m.Lport,
			laddr: "localhost",
			lport: m.Lport,
		}
		channel, reqs, err := conn.Conn.OpenChannel("forwarded-tcpip", ssh.Marshal(fm))
		if err != nil {
			log.Fatal(err.Error())
		}

		go ssh.DiscardRequests(reqs)

		portListener, err := sshClientConn.Listen("tcp", appConfig.RemoteForwardAddress)
		if err != nil {
			log.Fatal(err.Error())
		}

		go func() {
			for {
				sshConn, err := portListener.Accept()
				if err != nil {
					log.Fatal(err.Error())
				}

				// Copy localConn.Reader to sshConn.Writer
				go func(sshConn net.Conn) {
					_, err := io.Copy(sshConn, channel)
					if err != nil {
						log.Println("io.Copy failed: %v", err)
						sshConn.Close()
						return
					}
				}(sshConn)

				// Copy sshConn.Reader to localConn.Writer
				go func(sshConn net.Conn) {
					_, err := io.Copy(channel, sshConn)
					if err != nil {
						log.Println("io.Copy failed: %v", err)
						sshConn.Close()
						return
					}
				}(sshConn)
			}
		}()
		req.Reply(true, nil)
	}
}
