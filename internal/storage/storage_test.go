// The codec helpers shared by the storage drivers, tested directly (the
// -coverpkg aggregation otherwise attributes their coverage only indirectly
// through the drivers).
package storage

import (
	"bytes"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"thebasstoon.com/wgenrol/internal/wireguard"
)

func TestSerializeAllowedIPs(t *testing.T) {
	got := SerializeAllowedIPs([]netip.Prefix{
		netip.MustParsePrefix("10.64.0.5/24"), // unmasked input
		netip.MustParsePrefix("fd00::5/128"),
	})
	if want := "10.64.0.0/24,fd00::5/128"; got != want {
		t.Fatalf("expected %q, got %q (entries must be masked)", want, got)
	}
	if SerializeAllowedIPs(nil) != "" {
		t.Fatal("an empty list must serialize to an empty string")
	}
}

func TestParseAllowedIPs(t *testing.T) {
	// Empty segments (e.g. from hand-written CSVs) are skipped; entries are
	// trimmed and masked.
	ips, err := ParseAllowedIPs(" 10.64.0.5/32 , ,fd00::5/64,")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.64.0.5/32", "fd00::/64"}
	if len(ips) != len(want) {
		t.Fatalf("expected %d entries, got %v", len(want), ips)
	}
	for i := range want {
		if ips[i].String() != want[i] {
			t.Errorf("position %d: expected %s, got %s", i, want[i], ips[i].String())
		}
	}

	if empty, err := ParseAllowedIPs(""); err != nil || len(empty) != 0 {
		t.Fatalf("empty input must yield an empty list: %v, %v", empty, err)
	}

	if _, err := ParseAllowedIPs("not-a-cidr"); err == nil || !strings.Contains(err.Error(), "Failed to parse stored AllowedIPs") {
		t.Fatalf("expected an unparseable-prefix error, got %v", err)
	}
}

func TestPskOrNull(t *testing.T) {
	if PskOrNull(nil) != nil {
		t.Fatal("a nil PSK must map to a NULL parameter")
	}
	key := wireguard.Key{7}
	blob, ok := PskOrNull(&key).([]byte)
	if !ok || !reflect.DeepEqual(blob, []byte(key[:])) {
		t.Fatalf("expected the raw key bytes, got %v", blob)
	}
}

func TestKeyFromBlob(t *testing.T) {
	key, err := KeyFromBlob(bytes.Repeat([]byte{1}, 32), "pubkey")
	if err != nil {
		t.Fatal(err)
	}
	if key[0] != 1 {
		t.Fatalf("unexpected key contents: %v", key)
	}
	if _, err := KeyFromBlob([]byte("short"), "pubkey"); err == nil || !strings.Contains(err.Error(), "(pubkey)") {
		t.Fatalf("expected a corrupt-data error naming the column, got %v", err)
	}
	if _, err := KeyFromBlob([]byte("short"), "psk"); err == nil || !strings.Contains(err.Error(), "(psk)") {
		t.Fatalf("expected a corrupt-data error naming the psk column, got %v", err)
	}
}
