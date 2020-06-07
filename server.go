package main

import (
	"bytes"
	"context"
	"fmt"
	"github.com/candlerb/sshtokenca/util"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
	"log"
	"net"
	"strings"
	"time"
)

// Serve the SSH Agent Forwarding Certificate Authority Server. The
// server requires connections to have user_principals plus public key
// or fingerprint registered in the
// settings. The handleConnections goroutine prints information to the
// the client terminal and adds a certificate to the user's ssh
// forwarded agent.
// The ssh server is drawn from the example in the ssh server docs at
// https://godoc.org/golang.org/x/crypto/ssh#ServerConn and the Scalingo
// blog posting at
// https://scalingo.com/blog/writing-a-replacement-to-openssh-using-go-22.html
func Serve(options Options, privateKey ssh.Signer, caKey ssh.Signer, settings util.Settings) {
	ctx := context.Background()

	// configure server
	sshConfig := &ssh.ServerConfig{
		// public key callback taken directly from ssh.ServerConn example
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			u, err := settings.UserByName(c.User())
			if err != nil {
				return nil, err
			}
			for _, key := range u.PublicKeys() {
				if bytes.Equal(pubKey.Marshal(), key.Marshal()) {
					return nil, nil
				}
			}
			return nil, fmt.Errorf("unknown public key")
		},
		KeyboardInteractiveCallback: func(c ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			if settings.OpenIDC == nil {
				return nil, fmt.Errorf("OpenIDC not configured")
			}
			instruction := "Visit this URL to obtain auth code:\n" + settings.OpenIDC.AuthCodeURL("") + "\n"
			answers, err := client(c.User(), instruction, []string{"Enter your auth code: "}, []bool{true})
			if err != nil {
				return nil, err
			}
			if len(answers) != 1 {
				return nil, fmt.Errorf("Unexpected number of answers: %d", len(answers))
			}
			idToken, err := settings.OpenIDC.CodeToIDToken(ctx, answers[0])
			if err != nil {
				return nil, err
			}
			u, err := settings.UserByName(c.User())
			if err != nil {
				return nil, err
			}
			if idToken.Subject != u.OIDCSubject {
				// User authenticated successfully but we don't know them.
				// Let them know their Subject anyway
				msg := fmt.Sprintf("Not authorized for this service: %v", idToken.Subject)
				_, err := client(c.User(), msg, []string{}, []bool{})
				if err != nil {
					return nil, err
				}
				return nil, fmt.Errorf("unknown oidc subject %s for %q", idToken.Subject, c.User())
			}
			return nil, nil
		},
	}
	sshConfig.AddHostKey(privateKey)

	// setup net listener
	log.Printf("\n\nStarting server connection for %s...", settings.Organisation)
	addr_port := strings.Join([]string{options.IPAddress, options.Port}, ":")
	listener, err := net.Listen("tcp", addr_port)
	if err != nil {
		log.Fatalf("Failed to listen on %s", addr_port)
	} else {
		log.Printf("Listening on %s", addr_port)
	}

	for {
		// make tcp connection
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept incoming connection (%s)", err)
			continue
		}

		// provide handshake
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, sshConfig)
		if err != nil {
			log.Printf("failed to handshake (%s)", err)
			continue
		}
		go ssh.DiscardRequests(reqs)

		// report remote address, user and key
		log.Printf("new ssh connection for user %s from %s (%s)", sshConn.User(), sshConn.RemoteAddr(), sshConn.ClientVersion())

		// extract user
		user, err := settings.UserByName(sshConn.User())
		if err != nil {
			log.Printf("INTERNAL ERROR: unable to find user %s", sshConn.User())
			sshConn.Close()
			continue
		}

		message, err := addCertificate(user, settings, sshConn, caKey)

		// accept all channels
		go handleChannels(chans, user, settings, sshConn, message, err)
	}
}

func addCertificate(user *util.UserPrincipals, settings util.Settings,
	sshConn *ssh.ServerConn, caKey ssh.Signer) (string, error) {
	// https://lists.gt.net/openssh/dev/72190
	agentChan, reqs, err := sshConn.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		return "Could not open agent channel. Connect using agent forwarding (ssh -A)", err
	}
	defer agentChan.Close()
	go ssh.DiscardRequests(reqs)

	agentConn := agent.NewClient(agentChan)

	err = addCertToAgent(agentConn, caKey, user, settings)
	if err != nil {
		log.Printf("certificate creation error %s\n", err)
		return "Certification creation error", err
	}

	return "Certification generation complete. Run 'ssh-add -l' to view", nil
}

// write to the connection terminal, ignoring errors
func termWriter(t *terminal.Terminal, s string) {
	_, _ = t.Write([]byte(s + "\n"))
}

// close the ssh client connection politely
func chanCloser(c ssh.Channel, isError bool) {
	var status = struct {
		Status uint32
	}{uint32(0)}
	if isError == true {
		status.Status = 1
	}
	// https://godoc.org/golang.org/x/crypto/ssh#Channel
	// https://tools.ietf.org/html/rfc4254#section-6.10
	_, err := c.SendRequest("exit-status", false, ssh.Marshal(status))
	if err != nil {
		log.Printf("Could not close ssh client connection: %s", err)
	}
	c.Close()
}

// Service the incoming channel. The certErr channel indicates when the
// certificate has finished generation
func handleChannels(chans <-chan ssh.NewChannel, user *util.UserPrincipals,
	settings util.Settings, sshConn *ssh.ServerConn, message string, result error) {

	defer sshConn.Close()
	limit := time.After(10 * time.Second)

	// Only accept a *single* channel request
	select {
	case thisChan := <-chans:
		if thisChan == nil {
			return
		}

		if thisChan.ChannelType() != "session" {
			thisChan.Reject(ssh.Prohibited, "channel type is not a session")
			return
		}

		// accept channel
		ch, reqs, err := thisChan.Accept()
		if err != nil {
			log.Println("did not accept channel request", err)
			return
		}

		// wait for a "shell" request to return the result text
		for {
			select {
			case req := <-reqs:
				if req == nil {
					return
				}
				log.Printf("Received request: %s\n", req.Type)
				ok := (req.Type == "auth-agent-req@openssh.com") ||
					(req.Type == "pty-req") ||
					(req.Type == "shell")
				if req.WantReply {
					req.Reply(ok, nil)
				}
				if req.Type == "shell" {
					// terminal
					term := terminal.NewTerminal(ch, "")
					termWriter(term, settings.Banner)
					termWriter(term, fmt.Sprintf("welcome, %s", user.Name))
					if result != nil {
						termWriter(term, result.Error())
					}
					termWriter(term, message)
					termWriter(term, "goodbye\n")
					log.Println("closing the connection")
					chanCloser(ch, result != nil)
				}
			case <-limit:
				// Forced timeout, close session
				return
			}
		}
	case <-limit:
		// Forced timeout, close session
		return
	}
}
