package util

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	yaml "gopkg.in/yaml.v3"
	"os"
	"time"
)

const minvalidity = 1 * time.Minute
const maxvalidity = 24 * time.Hour

// Restrict the certificate extensions to those commonly supported as
// defined at https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
// Note that the extensions each (only) use an empty string for their
// value
var permittedExtensions = map[string]string{
	// "no-presence-required": "", // only U2F/Fido
	"permit-agent-forwarding": "",
	"permit-port-forwarding":  "",
	"permit-pty":              "",
	"permit-X11-forwarding":   "",
	"permit-user-rc":          "",
}

type UserPrincipals struct {
	Name          string   `yaml:"name"`
	AuthorizedKey string   `yaml:"authorized_key"`
	Fingerprint   string   `yaml:"fingerprint"`
	OIDCSubject   string   `yaml:"oidc_subject"`
	Principals    []string `yaml:"principals,flow"`

	publicKeys []ssh.PublicKey
}

type Settings struct {
	Validity     time.Duration     `yaml:"validity"`
	Organisation string            `yaml:"organisation"`
	Banner       string            `yaml:"banner"`
	Extensions   map[string]string `yaml:"extensions,flow"`
	Users        []*UserPrincipals `yaml:"user_principals"`
	OpenIDC      *OpenIDC          `yaml:"oidc"`
	usersByName  map[string]*UserPrincipals
}

// Load a settings yaml file into a Settings struct
func SettingsLoad(yamlFilePath string) (Settings, error) {
	var s = Settings{}

	file, err := os.Open(yamlFilePath)
	if err != nil {
		return s, err
	}
	defer file.Close()

	dec := yaml.NewDecoder(file)
	dec.KnownFields(true)
	err = dec.Decode(&s)
	if err != nil {
		return s, err
	}

	if len(s.Users) == 0 {
		return s, errors.New("no valid users found in yaml file")
	}

	// run validation
	err = s.validate()
	if err != nil {
		return s, err
	}

	// build map of keys by name
	err = s.buildNameMap()
	if err != nil {
		return s, err
	}

	// prepare OpenID
	if s.OpenIDC != nil {
		err = s.OpenIDC.Init(context.Background())
		if err != nil {
			return s, err
		}
	}

	return s, nil
}

// Extract a user's UserPrincipals struct
func (s *Settings) UserByName(name string) (*UserPrincipals, error) {
	var up = &UserPrincipals{}
	up, ok := s.usersByName[name]
	if !ok {
		return up, fmt.Errorf("user %s not found", name)
	}
	return up, nil
}

// build map by name
func (s *Settings) buildNameMap() error {
	s.usersByName = map[string]*UserPrincipals{}
	for _, u := range s.Users {
		if _, ok := s.usersByName[u.Name]; ok {
			return fmt.Errorf("duplicate entry for user %s", u.Name)
		}
		s.usersByName[u.Name] = u
	}
	return nil
}

// Validate the certificate extensions, validity period and user records
func (s *Settings) validate() error {

	// check validity period
	if s.Validity < minvalidity {
		return fmt.Errorf("validity is below minimum validity")
	} else if s.Validity > maxvalidity {
		return fmt.Errorf("validity is above maximum validity")
	}

	// check extensions meet permittedExtensions
	for k, v := range s.Extensions {
		val, ok := permittedExtensions[k]
		if !ok {
			return fmt.Errorf("extension %s not permitted", k)
		}
		if v != val {
			return fmt.Errorf("value '%s' for key %s not permitted, expected %s", val, k, v)
		}
	}

	// check users
	foundOIDC := false
	for _, v := range s.Users {
		if v.Name == "" {
			return errors.New("user provided with empty name")
		} else if len(v.Principals) == 0 {
			return fmt.Errorf("user %s provided with no principals", v.Name)
		} else if v.AuthorizedKey == "" && v.OIDCSubject == "" {
			return fmt.Errorf("user %s has no authorized_key or oidc_subject", v.Name)
		}

		if v.AuthorizedKey != "" {
			keys, err := LoadAuthorizedKeysBytes([]byte(v.AuthorizedKey))
			if err != nil {
				return err
			}
			if len(keys) != 1 {
				return fmt.Errorf("user %s unexpected number of keys in authorized_key entry (%d)", v.Name, len(keys))
			}
			if v.Fingerprint != "" {
				fp := string(ssh.FingerprintSHA256(keys[0]))
				if v.Fingerprint != fp {
					return fmt.Errorf("user %s mismatched fingerprint and public key", v.Name)
				}
			}
			v.publicKeys = keys
		} else if v.Fingerprint != "" {
			return fmt.Errorf("user %s has fingerprint but no authorized_key", v.Name)
		}

		if v.OIDCSubject != "" {
			foundOIDC = true
		}
	}

	if foundOIDC && s.OpenIDC == nil {
		return errors.New("oidc authorization used but oidc provider not configured")
	}

	return nil
}

func (up *UserPrincipals) PublicKeys() []ssh.PublicKey {
	return up.publicKeys
}
