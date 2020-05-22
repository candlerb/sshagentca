package main

import (
	"context"
	"fmt"
	"github.com/candlerb/sshagentca/util"
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
			_, err := settings.UserByFingerprint(ssh.FingerprintSHA256(pubKey))
			if err == nil {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
					},
				}, nil
			}
			return nil, fmt.Errorf("unknown public key %s for %q", ssh.FingerprintSHA256(pubKey), c.User())
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
			_, err = settings.UserByOIDCSubject(idToken.Subject)
			if err != nil {
				// User authenticated successfully but we don't know them.
				// Let them know their Subject anyway
				msg := fmt.Sprintf("Not authorized for this service: %v", idToken.Subject)
				_, err := client(c.User(), msg, []string{}, []bool{})
				if err != nil {
					return nil, err
				}
				return nil, fmt.Errorf("unknown oidc subject %s for %q", idToken.Subject, c.User())
			}
			return &ssh.Permissions{
				Extensions: map[string]string{
					"oidc-sub": idToken.Subject,
				},
			}, nil
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

		// extract user
		// TODO: if both public key and OIDC configured for same user, enforce both
		user, err := settings.UserByFingerprint(sshConn.Permissions.Extensions["pubkey-fp"])
		if err != nil {
			user, err = settings.UserByOIDCSubject(sshConn.Permissions.Extensions["oidc-sub"])
		}
		if err != nil {
			log.Printf("verification error from unknown user %v", sshConn.Permissions.Extensions)
			sshConn.Close()
			continue
		}

		// report remote address, user and key
		log.Printf("new ssh connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
		log.Printf("user %s logged in with %v", user.Name, sshConn.Permissions.Extensions)

		// https://lists.gt.net/openssh/dev/72190
		agentChan, reqs, err := sshConn.OpenChannel("auth-agent@openssh.com", nil)
		if err != nil {
			log.Printf("Could not open agent channel %s", err)
			sshConn.Close()
			continue
		}
		agentConn := agent.NewClient(agentChan)

		// discard incoming out-of-band requests
		go ssh.DiscardRequests(reqs)

		// accept all channels
		go handleChannels(chans, user, settings, sshConn, agentConn, caKey)
	}
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
	_, err := c.SendRequest("exit-status", false, ssh.Marshal(status))
	if err != nil {
		log.Printf("Could not close ssh client connection: %s", err)
	}
}

// Service the incoming channel. The certErr channel indicates when the
// certificate has finished generation
func handleChannels(chans <-chan ssh.NewChannel, user *util.UserPrincipals,
	settings util.Settings, sshConn *ssh.ServerConn, agentConn agent.ExtendedAgent,
	caKey ssh.Signer) {

	defer sshConn.Close()

	for thisChan := range chans {
		if thisChan.ChannelType() != "session" {
			thisChan.Reject(ssh.Prohibited, "channel type is not a session")
			return
		}

		// accept channel
		ch, reqs, err := thisChan.Accept()
		defer ch.Close()
		if err != nil {
			log.Println("did not accept channel request", err)
			return
		}

		// only respond to ssh agent forwarding type requests
		req := <-reqs
		if req.Type != "auth-agent-req@openssh.com" {
			ch.Write([]byte("request type not supported\n"))
			return
		}

		// terminal
		term := terminal.NewTerminal(ch, "")
		termWriter(term, settings.Banner)
		termWriter(term, fmt.Sprintf("welcome, %s", user.Name))

		// add certificate to agent, let the user know, then close the
		// connection
		err = addCertToAgent(agentConn, caKey, user, settings)
		if err != nil {
			log.Printf("certificate creation error %s\n", err)
			termWriter(term, "certificate creation error")
			termWriter(term, "goodbye\n")
			chanCloser(ch, true)
		} else {
			log.Printf("certificate creation and insertion in agent done\n")
			termWriter(term, "certificate generation complete")
			termWriter(term, "run 'ssh-add -l' to view")
			termWriter(term, "goodbye\n")
			chanCloser(ch, false)
		}
		time.Sleep(250 * time.Millisecond)
		log.Println("closing the connection")
		sshConn.Close()
		return
	}
}
