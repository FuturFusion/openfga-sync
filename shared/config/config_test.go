package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v4"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yml")

	err := os.WriteFile(path, []byte(content), 0o600)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	return path
}

func TestLoad(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, `
daemon:
  interval: 5m
  debug: true
  dry_run: true

sources:
  - name: corp-ad
    type: ldap
    ldap:
      url: ldaps://ad.example.com
      urls: [ldaps://ad02.example.com]
      bind_dn: CN=svc,DC=example,DC=com
      bind_password: secret
      group_base_dn: OU=Incus,DC=example,DC=com
      user_transforms: [lower]
      role_transforms: [lower]
      nested_groups: true
      sync_roles: true
      roles:
        - pattern: "^(.+)-admin$"
          grants:
            - relation: user

  - name: sso
    type: rauthy
    rauthy:
      url: https://sso.example.com
      api_key: name$secret
      role_pattern: "^incus-"
      sync_roles: true

  - name: idp
    type: zitadel
    zitadel:
      url: https://idp.example.com
      api_token: pat1
      sync_roles: true
      roles:
        - pattern: "^(.+)-admin$"
          grants:
            - relation: admin

openfga:
  url: http://127.0.0.1:8080
  api_token: token1
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if time.Duration(cfg.Daemon.Interval) != 5*time.Minute {
		t.Errorf("Unexpected interval: %v", cfg.Daemon.Interval)
	}

	if cfg.Daemon.StateDir != "/var/lib/openfga-sync" {
		t.Errorf("Unexpected state directory: %q", cfg.Daemon.StateDir)
	}

	if !cfg.Daemon.Debug || !cfg.Daemon.DryRun {
		t.Errorf("Unexpected daemon modes: %+v", cfg.Daemon)
	}

	if cfg.OpenFGA.Authoritative {
		t.Error("Expected authoritative mode to be disabled by default")
	}

	if cfg.OpenFGA.SkipMissingObjects {
		t.Error("Expected skip_missing_objects to default to false")
	}

	ldap := cfg.Sources[0].LDAP
	if !reflect.DeepEqual(ldap.URLs, []string{"ldaps://ad.example.com", "ldaps://ad02.example.com"}) {
		t.Errorf("Unexpected LDAP URLs: %v", ldap.URLs)
	}

	if ldap.GroupFilter != "(objectClass=group)" || ldap.GroupNameAttribute != "cn" || ldap.MemberAttribute != "member" || ldap.PageSize != 1000 {
		t.Errorf("Unexpected LDAP defaults: %+v", ldap)
	}

	if !reflect.DeepEqual(ldap.UserTransforms, []string{"lower"}) || !reflect.DeepEqual(ldap.RoleTransforms, []string{"lower"}) || !ldap.NestedGroups {
		t.Errorf("Unexpected LDAP options: %+v", ldap)
	}

	if ldap.Roles[0].Grants[0].Object != "project:${1}" {
		t.Errorf("Unexpected grant object default: %q", ldap.Roles[0].Grants[0].Object)
	}

	zitadel := cfg.Sources[2].Zitadel
	if zitadel.UserField != "email" {
		t.Errorf("Unexpected user field default: %q", zitadel.UserField)
	}
}

func TestJSON(t *testing.T) {
	t.Parallel()

	content := `{
  "daemon": {"interval": "5m", "state_dir": "/tmp/state"},
  "sources": [
    {"name": "sso", "type": "rauthy", "rauthy": {"url": "https://sso.example.com", "api_key": "key", "role_pattern": "^incus/", "sync_roles": true}}
  ],
  "openfga": {"url": "http://127.0.0.1:8080", "api_token": "secret", "authoritative": true, "skip_missing_objects": true}
}`

	cfg := &Config{}

	err := json.Unmarshal([]byte(content), cfg)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if time.Duration(cfg.Daemon.Interval) != 5*time.Minute {
		t.Errorf("Unexpected interval: %v", cfg.Daemon.Interval)
	}

	if cfg.Sources[0].Rauthy == nil || cfg.Sources[0].Rauthy.URL != "https://sso.example.com" {
		t.Errorf("Unexpected source: %+v", cfg.Sources[0])
	}

	if !cfg.OpenFGA.Authoritative || !cfg.OpenFGA.SkipMissingObjects {
		t.Errorf("Unexpected OpenFGA options: %+v", cfg.OpenFGA)
	}

	// The duration serializes back to its string form.
	serialized, err := json.Marshal(cfg.Daemon)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !strings.Contains(string(serialized), `"interval":"5m0s"`) {
		t.Errorf("Unexpected serialized daemon config: %s", serialized)
	}

	// The YAML form (as written back by IncusOS) keeps the string form too.
	serializedYAML, err := yaml.Marshal(cfg.Daemon)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !strings.Contains(string(serializedYAML), "interval: 5m0s") {
		t.Errorf("Unexpected serialized daemon config: %s", serializedYAML)
	}
}

func TestLoadInvalid(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"no sources": `
openfga:
  url: http://127.0.0.1:8080
`,
		"no rauthy sync mode": `
sources:
  - name: sso
    type: rauthy
    rauthy:
      url: https://sso.example.com
      api_key: key
openfga:
  url: http://127.0.0.1:8080
`,
		"no openfga": `
sources:
  - name: sso
    type: rauthy
    rauthy:
      url: https://sso.example.com
      api_key: key
      sync_roles: true
`,
		"bad source type": `
sources:
  - name: foo
    type: unknown
openfga:
  url: http://127.0.0.1:8080
`,

		"bad role pattern": `
sources:
  - name: corp-ad
    type: ldap
    ldap:
      url: ldaps://ad.example.com
      group_base_dn: OU=Incus,DC=example,DC=com
      sync_roles: true
      roles:
        - pattern: "(["
          grants:
            - relation: user
openfga:
  url: http://127.0.0.1:8080
`,
		"ldap url and domain": `
sources:
  - name: corp-ad
    type: ldap
    ldap:
      url: ldaps://ad.example.com
      domain: example.com
      group_base_dn: OU=Incus,DC=example,DC=com
      sync_groups: true
openfga:
  url: http://127.0.0.1:8080
`,
		"ldap bad group pattern": `
sources:
  - name: corp-ad
    type: ldap
    ldap:
      url: ldaps://ad.example.com
      group_base_dn: OU=Incus,DC=example,DC=com
      group_pattern: "(["
      sync_groups: true
openfga:
  url: http://127.0.0.1:8080
`,
		"ldap bad user transform": `
sources:
  - name: corp-ad
    type: ldap
    ldap:
      url: ldaps://ad.example.com
      group_base_dn: OU=Incus,DC=example,DC=com
      user_transforms: [title]
      sync_groups: true
openfga:
  url: http://127.0.0.1:8080
`,
		"ldap bad role transform": `
sources:
  - name: corp-ad
    type: ldap
    ldap:
      url: ldaps://ad.example.com
      group_base_dn: OU=Incus,DC=example,DC=com
      role_transforms: [title]
      sync_groups: true
openfga:
  url: http://127.0.0.1:8080
`,
		"ldap bad page size": `
sources:
  - name: corp-ad
    type: ldap
    ldap:
      url: ldaps://ad.example.com
      group_base_dn: OU=Incus,DC=example,DC=com
      page_size: -1
      sync_groups: true
openfga:
  url: http://127.0.0.1:8080
`,
		"ldap bad url scheme": `
sources:
  - name: corp-ad
    type: ldap
    ldap:
      urls: [ldaps://ad01.example.com, https://ad02.example.com]
      group_base_dn: OU=Incus,DC=example,DC=com
      sync_groups: true
openfga:
  url: http://127.0.0.1:8080
`,
		"zitadel no roles": `
sources:
  - name: idp
    type: zitadel
    zitadel:
      url: https://idp.example.com
      api_token: pat
      sync_roles: true
openfga:
  url: http://127.0.0.1:8080
`,
		"zitadel bad user field": `
sources:
  - name: idp
    type: zitadel
    zitadel:
      url: https://idp.example.com
      api_token: pat
      user_field: username
      sync_roles: true
      roles:
        - pattern: "^(.+)-admin$"
          grants:
            - relation: admin
openfga:
  url: http://127.0.0.1:8080
`,
	}

	for name, content := range cases {
		_, err := Load(writeConfig(t, content))
		if err == nil {
			t.Errorf("Expected an error for %q", name)
		}
	}
}
