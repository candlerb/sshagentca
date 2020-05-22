package main

import (
	"fmt"
	"github.com/candlerb/sshtokenca/util"
	flags "github.com/jessevdk/go-flags"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"net"
	"os"
)

const VERSION = "0.0.5-candlerb"
const usage = `<options> <yamlfile>

SSH Agent CA version %s

A proof-of-concept SSH server forwarded agent certificate authority

    sshtokenca -h
    sshtokenca -p <privatekey> -c <caprivatekey>
               -i <ipaddress> -p <port> settings.yaml

Application Arguments:


 `

// flag options
type Options struct {
	PrivateKey   string `short:"t" long:"privateKey" required:"true" description:"server ssh private key (password protected)"`
	CAPrivateKey string `short:"c" long:"caPrivateKey" required:"true" description:"certificate authority private key (password protected)"`
	IPAddress    string `short:"i" long:"ipAddress" default:"0.0.0.0" description:"ipaddress"`
	Port         string `short:"p" long:"port" default:"2222" description:"port"`
	Args         struct {
		YamlFile string `description:"settings yaml file"`
	} `positional-args:"yes" required:"yes"`
}

func hardexit(msg string) {
	fmt.Printf("\n\n> %s\n\nAborting startup.\n", msg)
	os.Exit(1)
}

func main() {

	var options Options
	var parser = flags.NewParser(&options, flags.Default)
	parser.Usage = fmt.Sprintf(usage, VERSION)

	if _, err := parser.Parse(); err != nil {
		os.Exit(1)
	}

	fmt.Println("SSH Agent CA")

	// load settings
	settings, err := util.SettingsLoad(options.Args.YamlFile)
	if err != nil {
		hardexit(fmt.Sprintf("Settings could not be loaded : %s", err))
	}

	// check ip
	if net.IP(options.IPAddress) == nil {
		hardexit(fmt.Sprintf("Invalid ip address %s", options.IPAddress))
	}

	// load server private key
	privateKey, err := util.LoadPrivateKey(options.PrivateKey)
	_, passphraseNeeded := err.(*ssh.PassphraseMissingError)
	if passphraseNeeded {
		fmt.Printf("\nServer private key password: ")
		pvtPW, err2 := terminal.ReadPassword(0)
		if err2 != nil {
			hardexit(fmt.Sprintf("Could not read password: %s", err))
		}
		privateKey, err = util.LoadPrivateKeyWithPassword(options.PrivateKey, pvtPW)
	}
	if err != nil {
		hardexit(fmt.Sprintf("Private key could not be loaded, %s", err))
	}

	// load certificate authority private key
	caKey, err := util.LoadPrivateKey(options.CAPrivateKey)
	_, passphraseNeeded = err.(*ssh.PassphraseMissingError)
	if passphraseNeeded {
		fmt.Printf("\nCertificate Authority private key password: ")
		caPW, err2 := terminal.ReadPassword(0)
		if err2 != nil {
			hardexit(fmt.Sprintf("Could not read password: %s", err))
		}
		caKey, err = util.LoadPrivateKeyWithPassword(options.CAPrivateKey, caPW)
	}
	if err != nil {
		hardexit(fmt.Sprintf("CA Private key could not be loaded, %s", err))
	}

	Serve(options, privateKey, caKey, settings)
}
