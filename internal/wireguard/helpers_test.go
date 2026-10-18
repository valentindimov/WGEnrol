package wireguard

import (
	"crypto/rand"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// makeKey returns a new random 32-byte key.
func makeKey(t *testing.T) Key {
	t.Helper()
	var key Key
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	return key
}

// writeConf writes a minimal [Interface] config plus the given peer block to a
// temp file and returns its path. Fixture builder for ImportPeersFromINI.
func writeConf(t *testing.T, peerBlock string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "wg.conf")
	conf := "[Interface]\nPrivateKey = " + makeKey(t).String() + "\nAddress = 10.64.0.1/24\nListenPort = 51820\n\n" + peerBlock
	if err := os.WriteFile(p, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// prefixes parses CIDR strings into a []netip.Prefix.
func prefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}
