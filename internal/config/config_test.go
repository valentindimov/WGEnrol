package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConfig writes YAML to a temp file and returns the path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// baseConfig is a minimal valid configuration. It omits storage.backend, so
// the sqlite default applies.
const baseConfig = `server:
  listenOn: "127.0.0.1:8080"
  tls:
    enabled: false
admin:
  users:
    admin: "$2a$08$noE9l0k/bSRj0cyRaVsDsue4L2WEmHP9pHxfGOJ026xEttfFn3TFq"
  ipFilter: [ "10.64.0.0/16", " 10.65.1.5/24 " ]
smtp:
  enabled: false
storage:
  file: "/tmp/wgenrol-test.db"
wireguard:
  ifname: "wgenrol-test"
advertise:
  endpoint: "127.0.0.1:51820"
  additionalSubnets: [ "10.164.0.1/16" ]
  advertiseDNS: false
`

// smtpConfig is baseConfig with SMTP enabled and all of its fields set.
const smtpConfig = `server:
  listenOn: "127.0.0.1:8080"
  tls:
    enabled: false
admin:
  users:
    admin: "$2a$08$noE9l0k/bSRj0cyRaVsDsue4L2WEmHP9pHxfGOJ026xEttfFn3TFq"
smtp:
  enabled: true
  host: "smtp.example.com"
  port: 587
  user: "u@example.com"
  password: "pw"
  from: "u@example.com"
storage:
  file: "/tmp/wgenrol-test.db"
wireguard:
  ifname: "wgenrol-test"
advertise:
  endpoint: "127.0.0.1:51820"
`

func TestParseConfigFileSuccess(t *testing.T) {
	cfg, err := ParseConfigFile(writeConfig(t, baseConfig))
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if *cfg.Server.ListenOn != "127.0.0.1:8080" {
		t.Errorf("ListenOn not parsed: %v", *cfg.Server.ListenOn)
	}
	if len(cfg.Admin.Users) != 1 {
		t.Errorf("users not parsed: %v", cfg.Admin.Users)
	}
	if *cfg.Wireguard.Ifname != "wgenrol-test" {
		t.Errorf("ifname not parsed: %v", *cfg.Wireguard.Ifname)
	}
	if cfg.Storage.Backend != "sqlite" || cfg.Storage.File == nil || *cfg.Storage.File != "/tmp/wgenrol-test.db" {
		t.Errorf("storage block not parsed: backend=%q file=%v", cfg.Storage.Backend, cfg.Storage.File)
	}
	if *cfg.Advertise.Endpoint != "127.0.0.1:51820" {
		t.Errorf("endpoint not parsed: %v", *cfg.Advertise.Endpoint)
	}
}

func TestParseConfigFileFullSMTP(t *testing.T) {
	cfg, err := ParseConfigFile(writeConfig(t, smtpConfig))
	if err != nil {
		t.Fatalf("valid SMTP config rejected: %v", err)
	}
	if !cfg.Smtp.Enabled {
		t.Error("Smtp.Enabled not parsed")
	}
	if *cfg.Smtp.Port != 587 || *cfg.Smtp.Host != "smtp.example.com" {
		t.Errorf("SMTP fields not parsed: %v / %v", *cfg.Smtp.Host, *cfg.Smtp.Port)
	}
}

// pgConfig is a valid configuration using the postgres backend.
const pgConfig = `server:
  listenOn: "127.0.0.1:8080"
  tls:
    enabled: false
admin:
  users:
    admin: "$2a$08$noE9l0k/bSRj0cyRaVsDsue4L2WEmHP9pHxfGOJ026xEttfFn3TFq"
smtp:
  enabled: false
storage:
  backend: postgres
  dsn: "postgres://u:p@localhost/wgenrol"
wireguard:
  ifname: "wgenrol-test"
advertise:
  endpoint: "127.0.0.1:51820"
`

func TestParseConfigFileRequiredFields(t *testing.T) {
	fullSMTP := smtpConfig
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"listenOn", strings.Replace(baseConfig, `listenOn: "127.0.0.1:8080"`, "", 1), "server.listenOn parameter is required"},
		{"ifname", strings.Replace(baseConfig, `ifname: "wgenrol-test"`, "", 1), "wireguard.ifname parameter is required"},
		{"storageFileMissing", strings.Replace(baseConfig, `  file: "/tmp/wgenrol-test.db"`+"\n", "", 1), "storage.file is required"},
		{"endpoint", strings.Replace(baseConfig, `endpoint: "127.0.0.1:51820"`, "", 1), "advertise.endpoints parameter is required"},
		{"ipFilterInvalid", strings.Replace(baseConfig, `"10.64.0.0/16"`, `"not-a-subnet"`, 1), "netip"},
		{"additionalSubnetsInvalid", strings.Replace(baseConfig, `"10.164.0.1/16"`, `"not-a-subnet"`, 1), "netip"},
		{"tlsWithoutCerts", strings.Replace(baseConfig, "enabled: false", "enabled: true", 1), "server.tls.certFile"},
		{"smtpNoHost", strings.Replace(fullSMTP, `host: "smtp.example.com"`, "", 1), "smtp.host parameter is required"},
		{"smtpNoPort", strings.Replace(fullSMTP, `port: 587`, "", 1), "smtp.port parameter is required"},
		{"smtpNoUser", strings.Replace(fullSMTP, `user: "u@example.com"`, "", 1), "smtp.user parameter is required"},
		{"smtpNoPassword", strings.Replace(fullSMTP, `password: "pw"`, "", 1), "smtp.password parameter is required"},
		{"smtpNoFrom", strings.Replace(fullSMTP, `from: "u@example.com"`, "", 1), "smtp.from parameter is required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseConfigFile(writeConfig(t, c.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q, got none", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("expected error containing %q, got %q", c.want, err.Error())
			}
		})
	}
}

func TestParseConfigFileInvalidYAML(t *testing.T) {
	if _, err := ParseConfigFile(writeConfig(t, "server: {listenOn: \"[unclosed\"")); err == nil {
		t.Fatal("expected a YAML parsing error")
	}
}

func TestParseConfigFileMissingFile(t *testing.T) {
	if _, err := ParseConfigFile(filepath.Join(t.TempDir(), "nope", "config.yaml")); err == nil {
		t.Fatal("expected an error for a missing config file")
	}
}

func TestStorageBackendDefaultsToSqlite(t *testing.T) {
	cfg, err := ParseConfigFile(writeConfig(t, baseConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Storage.Backend != "sqlite" {
		t.Fatalf("expected default backend sqlite, got %q", cfg.Storage.Backend)
	}
}

func TestStoragePostgresHappy(t *testing.T) {
	cfg, err := ParseConfigFile(writeConfig(t, pgConfig))
	if err != nil {
		t.Fatalf("valid postgres config rejected: %v", err)
	}
	if cfg.Storage.Backend != "postgres" || cfg.Storage.Dsn == nil || *cfg.Storage.Dsn != "postgres://u:p@localhost/wgenrol" {
		t.Fatalf("postgres storage not parsed: %+v", cfg.Storage)
	}
}

func TestStorageBackendValidation(t *testing.T) {
	cases := []struct {
		name       string
		yaml       string
		wantSubstr string
	}{
		{"unknown backend", strings.Replace(baseConfig, `  file: "/tmp/wgenrol-test.db"`, `  backend: mysql`, 1), "Unknown storage backend"},
		{"sqlite without file", strings.Replace(baseConfig, `  file: "/tmp/wgenrol-test.db"`+"\n", "", 1), "storage.file is required"},
		{"postgres without dsn", strings.Replace(pgConfig, `  dsn: "postgres://u:p@localhost/wgenrol"`+"\n", "", 1), "storage.dsn is required"},
		{"postgres with file", strings.Replace(pgConfig, `  backend: postgres`, `  backend: postgres`+"\n"+`  file: "/tmp/x.db"`, 1), "storage.file is only valid"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseConfigFile(writeConfig(t, c.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q, got none", c.wantSubstr)
			}
			if !strings.Contains(err.Error(), c.wantSubstr) {
				t.Fatalf("expected error containing %q, got %q", c.wantSubstr, err.Error())
			}
		})
	}
}

func TestParseIPNetList(t *testing.T) {
	nets, err := ParseIPNetList([]string{"10.64.0.0/16", " 10.65.1.5/24 ", "fd00::/64"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"10.64.0.0/16", "10.65.1.0/24", "fd00::/64"}
	for i, n := range nets {
		if n.String() != want[i] {
			t.Errorf("position %d: expected %s, got %s (entries must be trimmed and masked)", i, want[i], n.String())
		}
	}
	if empty, err := ParseIPNetList(nil); err != nil || len(empty) != 0 {
		t.Fatalf("empty input must yield an empty list: %v, %v", empty, err)
	}
	if _, err := ParseIPNetList([]string{"bad"}); err == nil {
		t.Fatal("expected an error for an unparseable prefix")
	}
}
