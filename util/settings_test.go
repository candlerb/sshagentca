package util

import (
	"testing"
)

func settingsLoad(t *testing.T) Settings {
	settings, err := SettingsLoad("../settings.example.yaml")
	if err != nil {
		t.Errorf("Could not parse yaml: %v", err)
	}
	return settings
}

func TestSettingsParse(t *testing.T) {
	settings := settingsLoad(t)
	t.Logf("Settings : %+v", settings)
	if len(settings.Users) != 2 {
		t.Errorf("unexpected user length encountered")
	}
}

func TestSettingsParse2(t *testing.T) {
	settings := settingsLoad(t)
	settings.Validity = minvalidity - 1
	err := settings.validate()
	t.Logf("Error (expected): %v", err)
	if err == nil {
		t.Errorf("Invalid validity did not cause an error")
	}
}

func TestSettingsParse3(t *testing.T) {
	settings := settingsLoad(t)
	settings.Validity = maxvalidity + 1
	err := settings.validate()
	t.Logf("Error (expected): %v", err)
	if err == nil {
		t.Errorf("Invalid validity did not cause an error")
	}
}

func TestSettingsParse4(t *testing.T) {
	settings := settingsLoad(t)
	settings.Extensions = map[string]string{}
	err := settings.validate()
	if err != nil {
		t.Errorf("empty extensions caused a problem: %v", err)
	}
}

func TestSettingsParse5(t *testing.T) {
	settings := settingsLoad(t)
	settings.Extensions["permit-agent-forwarding"] = "nonsense"
	err := settings.validate()
	t.Logf("Error (expected): %v", err)
	if err == nil {
		t.Errorf("should not allow nonsense value in extension")
	}
}

func TestSettingsParse6(t *testing.T) {
	settings := settingsLoad(t)
	settings.Extensions["random-extension"] = ""
	err := settings.validate()
	t.Logf("Error (expected): %v", err)
	if err == nil {
		t.Errorf("should not allow random extension")
	}
}

func TestSettingsParse7(t *testing.T) {
	settings := settingsLoad(t)
	settings.Users[0].OIDCSubject = "12345"
	err := settings.validate()
	t.Logf("Error (expected): %v", err)
	if err == nil {
		t.Errorf("should not allow oidc user without oidc provider")
	}
}

func TestSettingsParse8(t *testing.T) {
	settings := settingsLoad(t)
	settings.OpenIDC = &OpenIDC{
		Issuer:       "https://accounts.google.com",
		ClientID:     "XXXXXXXX",
		ClientSecret: "XXXXXXXX",
	}
	settings.Users[0].OIDCSubject = "12345"
	err := settings.validate()
	if err != nil {
		t.Errorf("unexpected error with oidc user: %v", err)
	}
}

func TestUserSettings1(t *testing.T) {
	settings := settingsLoad(t)
	if len(settings.Users[0].publicKeys) != 1 {
		t.Errorf("missing public key")
	}
	if len(settings.Users[0].publicKeys[0].Marshal()) < 500 {
		t.Errorf("bad public key length")
	}
}

func TestUserSettings2(t *testing.T) {
	settings := settingsLoad(t)
	settings.Users[1].Fingerprint = settings.Users[1].Fingerprint[:49]
	err := settings.validate()
	t.Logf("Error (expected): %v", err)
	if err == nil {
		t.Errorf("fingerprint length change test failed")
	}
}

func TestUserSettings3(t *testing.T) {
	settings := settingsLoad(t)
	settings.Users[0].Principals = []string{}
	err := settings.validate()
	t.Logf("Error (expected): %v", err)
	if err == nil {
		t.Errorf("empty principals error passed")
	}
}

func TestUserSettings4(t *testing.T) {
	settings := settingsLoad(t)
	settings.Users[1].AuthorizedKey = ""
	err := settings.validate()
	t.Logf("Error (expected): %v", err)
	if err == nil {
		t.Errorf("fingerprint without key error passed")
	}
}

func TestUserSettings5(t *testing.T) {
	settings := settingsLoad(t)
	if settings.Users[0].AuthorizedKey == "" {
		t.Errorf("This test requires an authorized key")
	}
	settings.Users[0].AuthorizedKey = settings.Users[0].AuthorizedKey + "\n" + settings.Users[1].AuthorizedKey
	err := settings.validate()
	t.Logf("Error (expected): %v", err)
	if err == nil {
		t.Errorf("multiple keys passed")
	}
}

func TestUserSettings6(t *testing.T) {
	settings := settingsLoad(t)
	name := settings.Users[0].Name
	_, err := settings.UserByName(name)
	if err != nil {
		t.Errorf("UserByNamelookup failed: %v", err)
	}
	_, err = settings.UserByName("nonexistent")
	if err == nil {
		t.Errorf("Invalid UserByName lookup succeeded")
	}
	_, err = settings.UserByName("")
	if err == nil {
		t.Errorf("Invalid UserByName lookup succeeded")
	}
}

func TestUserAuth1(t *testing.T) {
	settings := settingsLoad(t)
	settings.Users[0].AuthorizedKey = ""
	settings.Users[0].Fingerprint = ""
	settings.Users[0].OIDCSubject = ""
	err := settings.validate()
	if err == nil {
		t.Errorf("missing authorized_key and oidc_subject should not be allowed")
	}
}

func TestUserAuth2(t *testing.T) {
	settings := settingsLoad(t)
	if settings.Users[1].AuthorizedKey == "" || settings.Users[1].Fingerprint == "" {
		t.Errorf("This test required an authorized_key and fingerprint to be set")
	}
	fp := []byte(settings.Users[1].Fingerprint)
	fp[30] = '%'
	settings.Users[1].Fingerprint = string(fp)
	err := settings.validate()
	if err == nil {
		t.Errorf("fingerprints not matching authorized_key should not be allowed")
	}
}
