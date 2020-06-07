package util

import (
	"bytes"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
)

// load a private key from file
func LoadPrivateKey(filename string) (ssh.Signer, error) {

	fkey, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	sig, err := ssh.ParsePrivateKey(fkey)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// load a private key with password from file
func LoadPrivateKeyWithPassword(filename string, passphrase []byte) (ssh.Signer, error) {

	fkey, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	sig, err := ssh.ParsePrivateKeyWithPassphrase(fkey, passphrase)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// load a raw private key without password from file
func LoadPrivateKeyRaw(filename string) (interface{}, error) {

	fkey, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	sig, err := ssh.ParseRawPrivateKey(fkey)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// load authorized_keys from []byte
func LoadAuthorizedKeysBytes(authorizedKeysBytes []byte) ([]ssh.PublicKey, error) {

	// record the found authorized keys
	var akeys []ssh.PublicKey

	// from https://godoc.org/golang.org/x/crypto/ssh#ex-NewServerConn
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			i := bytes.IndexAny(authorizedKeysBytes, "\n")
			if i > 1 {
				authorizedKeysBytes = authorizedKeysBytes[0 : i-1]
			}
			return akeys, fmt.Errorf("Error parsing public key \"%s\": %s", authorizedKeysBytes, err)
		}
		akeys = append(akeys, pubKey)
		authorizedKeysBytes = rest
	}
	return akeys, nil
}
