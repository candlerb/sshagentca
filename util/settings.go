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
	Name string `yaml:"name"`
	// ssh.FingerprintSHA256
	Fingerprint   string   `yaml:"fingerprint"`
	AuthorizedKey string   `yaml:"authorized_key"`
	OIDCSubject   string   `yaml:"oidc_subject"`
	Principals    []string `yaml:"principals,flow"`
}

type Settings struct {
	Validity           time.Duration     `yaml:"validity"`
	Organisation       string            `yaml:"organisation"`
	Banner             string            `yaml:"banner"`
	Extensions         map[string]string `yaml:"extensions,flow"`
	Users              []*UserPrincipals `yaml:"user_principals"`
	OpenIDC            *OpenIDC          `yaml:"oidc"`
	usersByFingerprint map[string]*UserPrincipals
	usersByOIDCSubject map[string]*UserPrincipals
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

	// build map of keys by fingerprint
	err = s.buildFPMap()
	if err != nil {
		return s, err
	}

	// build map of keys by subject
	err = s.buildSubMap()
	if err != nil {
		return s, err
	}

	// prepare OpenID
	if s.OpenIDC != nil {
		err = s.OpenIDC.Init(context.Background())
		if err != nil {
			return s, err
		}
	} else if len(s.usersByOIDCSubject) > 0 {
		return s, errors.New("oidc provider not configured in yaml file")
	}

	return s, nil
}

// Extract a user's UserPrincipals struct by fingerprint
func (s *Settings) UserByFingerprint(fp string) (*UserPrincipals, error) {
	var up = &UserPrincipals{}
	up, ok := s.usersByFingerprint[fp]
	if !ok {
		return up, errors.New(fmt.Sprintf("user for fingerprint %s not found", fp))
	}
	return up, nil
}

// Extract a user's UserPrincipals struct by OIDC Subject
func (s *Settings) UserByOIDCSubject(sub string) (*UserPrincipals, error) {
	var up = &UserPrincipals{}
	up, ok := s.usersByOIDCSubject[sub]
	if !ok {
		return up, errors.New(fmt.Sprintf("user for subject %s not found", sub))
	}
	return up, nil
}

// build map by fingerprint
func (s *Settings) buildFPMap() error {
	s.usersByFingerprint = map[string]*UserPrincipals{}
	for _, u := range s.Users {
		if u.Fingerprint == "" {
			continue
		}
		if u0, ok := s.usersByFingerprint[u.Fingerprint]; ok {
			return errors.New(fmt.Sprintf("duplicate entry for key %s (users %s and %s)", u.Fingerprint, u0.Name, u.Name))
		}
		s.usersByFingerprint[u.Fingerprint] = u
	}
	return nil
}

// build map by subject
func (s *Settings) buildSubMap() error {
	s.usersByOIDCSubject = map[string]*UserPrincipals{}
	for _, u := range s.Users {
		if u.OIDCSubject == "" {
			continue
		}
		if u0, ok := s.usersByOIDCSubject[u.OIDCSubject]; ok {
			return errors.New(fmt.Sprintf("duplicate entry for subject %s (users %s and %s)", u.OIDCSubject, u0.Name, u.Name))
		}
		s.usersByOIDCSubject[u.OIDCSubject] = u
	}
	return nil
}

// Validate the certificate extensions, validity period and user records
// Generate fingerprint from authorized_key if required
func (s *Settings) validate() error {

	// check validity period
	if s.Validity < minvalidity {
		return errors.New(fmt.Sprintf("validity must be >=%s", minvalidity))
	} else if s.Validity > maxvalidity {
		return errors.New(fmt.Sprintf("validity must be <=%s", maxvalidity))
	}

	// check extensions meet permittedExtensions
	for k, v := range s.Extensions {
		val, ok := permittedExtensions[k]
		if !ok {
			return errors.New(fmt.Sprintf("extension %s not permitted", k))
		}
		if v != val {
			return errors.New(fmt.Sprintf("value '%s' for key %s not permitted, expected %s", val, k, v))
		}
	}

	// check users
	for _, v := range s.Users {
		if v.Name == "" {
			return errors.New("user provided with empty name")
		} else if len(v.Principals) == 0 {
			return errors.New(fmt.Sprintf("user %s provided with no principals", v.Name))
		}

		if v.AuthorizedKey != "" {
			keys, err := LoadAuthorizedKeysBytes([]byte(v.AuthorizedKey))
			if err != nil {
				return err
			}
			if len(keys) != 1 {
				return errors.New(fmt.Sprintf("user %s unexpected number of keys in authorized_keys entry (%d)", v.Name, len(keys)))
			}
			fp := string(ssh.FingerprintSHA256(keys[0]))
			if v.Fingerprint != "" && v.Fingerprint != fp {
				return errors.New(fmt.Sprintf("user %s mismatched fingerprint and authorized_key", v.Name))
			}
			v.Fingerprint = fp
		} else if v.Fingerprint == "" {
			return errors.New(fmt.Sprintf("user %s fingerprint and authorized_key missing", v.Name))
		} else if len(v.Fingerprint) != 50 {
			return errors.New(fmt.Sprintf("user %s fingerprint unexpected length", v.Name))
		} else if v.Fingerprint[:7] != "SHA256:" {
			return errors.New(fmt.Sprintf("user %s fingerprint does not start with SHA256:", v.Name))
		}
	}

	return nil

}
