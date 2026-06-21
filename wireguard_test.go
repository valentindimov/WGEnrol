package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/ini.v1"
)

func TestLoadValidPeer(t *testing.T) {
	p := writeConf(t, "# Alice\n[Peer]\nPublicKey = "+validKey()+"\nAllowedIPs = 10.64.0.2/32\n")
	conf, err := loadWgConf(p)
	if err != nil {
		t.Fatalf("valid peer rejected: %v", err)
	}
	if len(conf.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(conf.Peers))
	}
	for _, peer := range conf.Peers {
		if peer.Comment != "Alice" {
			t.Errorf("expected name 'Alice', got %q", peer.Comment)
		}
	}
}

func TestLoadRejectsInvalidKey(t *testing.T) {
	p := writeConf(t, "# bad\n[Peer]\nPublicKey = THIS-IS-NOT-A-VALID-KEY\nAllowedIPs = 10.64.0.2/32\n")
	_, err := loadWgConf(p)
	if err == nil || !strings.Contains(err.Error(), "Invalid peer") {
		t.Fatalf("expected 'Invalid peer' error, got: %v", err)
	}
}

func TestLoadRejectsMissingAllowedIPs(t *testing.T) {
	p := writeConf(t, "# no allowed ips\n[Peer]\nPublicKey = "+validKey()+"\n")
	_, err := loadWgConf(p)
	if err == nil || !strings.Contains(err.Error(), "AllowedIPs cannot be empty") {
		t.Fatalf("expected clean AllowedIPs error, got: %v", err)
	}
}

func TestLoadToleratesTrailingComma(t *testing.T) {
	p := writeConf(t, "# Alice\n[Peer]\nPublicKey = "+validKey()+"\nAllowedIPs = 10.64.0.2/32, 10.64.1.2/32,\n")
	conf, err := loadWgConf(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, peer := range conf.Peers {
		if len(peer.AllowedIps) != 2 {
			t.Fatalf("expected 2 allowed IPs, got %d", len(peer.AllowedIps))
		}
	}
}

// Documents an accepted limitation: a name comment placed INSIDE the [Peer]
// section (the wg-quick convention) is not read as the peer name; only a
// comment preceding the section header is. Change this consciously if ever
// supporting in-section names.
func TestImportInSectionCommentNotRead(t *testing.T) {
	p := writeConf(t, "[Peer]\n# Alice\nPublicKey = "+validKey()+"\nAllowedIPs = 10.64.0.2/32\n")
	conf, err := loadWgConf(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range conf.Peers {
		if peer.Comment != "" {
			t.Errorf("expected in-section comment to be unread, got %q", peer.Comment)
		}
	}
}

func TestDecodeKey(t *testing.T) {
	if _, err := decodeKey(validKey()); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	if _, err := decodeKey("not!base64!"); err == nil {
		t.Fatal("expected error for non-base64 key")
	}
	if _, err := decodeKey(base64.StdEncoding.EncodeToString(make([]byte, 16))); err == nil {
		t.Fatal("expected error for wrong-length key")
	}
}

func TestAllowedIpsAsNetList(t *testing.T) {
	peer := WgPeer{AllowedIps: prefixes("10.64.0.2/32", "fd00::2/128")}
	nets := peer.allowedIpsAsNetList()
	if len(nets) != 2 || nets[0].String() != "10.64.0.2/32" || nets[1].String() != "fd00::2/128" {
		t.Fatalf("unexpected net list: %+v", nets)
	}
}

// Commit deletes the "Peer" section before rewriting; this must remove ALL
// non-unique [Peer] sections, not just the first.
func TestDeleteSectionRemovesAllPeers(t *testing.T) {
	options := ini.LoadOptions{
		AllowNonUniqueSections:     true,
		AllowShadows:               true,
		AllowDuplicateShadowValues: true,
		AllowBooleanKeys:           true,
	}
	src := []byte("[Interface]\nPrivateKey = a\n\n[Peer]\nPublicKey = k1\n\n[Peer]\nPublicKey = k2\n")
	cfg, err := ini.LoadSources(options, src)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DeleteSection("Peer")
	if secs, _ := cfg.SectionsByName("Peer"); len(secs) != 0 {
		t.Fatalf("expected all Peer sections removed, %d remain", len(secs))
	}
}

func TestAtomicSaveRoundTrip(t *testing.T) {
	target := filepath.Join(t.TempDir(), "wg.conf")
	cfg := ini.Empty()
	sec, _ := cfg.NewSection("Interface")
	sec.NewKey("PrivateKey", validKey())
	if err := atomicSaveIniFile(cfg, target); err != nil {
		t.Fatal(err)
	}
	reloaded, err := ini.Load(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Section("Interface").Key("PrivateKey").String(); got != validKey() {
		t.Fatalf("round-trip mismatch: %q", got)
	}
}

// A failing CreateTemp (non-existent target dir) must return an error, not panic.
func TestAtomicSaveCreateTempFailure(t *testing.T) {
	target := filepath.Join(t.TempDir(), "no_such_subdir", "wg.conf")
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked instead of returning an error: %v", r)
		}
	}()
	if err := atomicSaveIniFile(ini.Empty(), target); err == nil {
		t.Fatal("expected an error for a non-existent target directory")
	}
}

// The directory handle opened for the best-effort fsync must be closed.
// Linux-only: relies on /proc/self/fd to count descriptors.
func TestAtomicSaveNoFDLeak(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fd counting via /proc is Linux-only")
	}
	target := filepath.Join(t.TempDir(), "wg.conf")
	countFds := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Skipf("cannot read /proc/self/fd: %v", err)
		}
		return len(entries)
	}
	if err := atomicSaveIniFile(ini.Empty(), target); err != nil {
		t.Fatal(err)
	}
	before := countFds()
	for i := 0; i < 50; i++ {
		if err := atomicSaveIniFile(ini.Empty(), target); err != nil {
			t.Fatal(err)
		}
	}
	if after := countFds(); after-before > 10 {
		t.Fatalf("fd leak: %d new descriptors after 50 saves", after-before)
	}
}
