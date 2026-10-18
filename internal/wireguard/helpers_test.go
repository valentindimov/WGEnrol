package wireguard

import (
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// validKey returns a syntactically valid (32-byte) WireGuard key in std base64.
func validKey() string { return base64.StdEncoding.EncodeToString(make([]byte, 32)) }

// writeConf writes a minimal [Interface] config plus the given peer block to a
// temp file and returns its path.
func writeConf(t *testing.T, peerBlock string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "wg.conf")
	conf := "[Interface]\nPrivateKey = " + validKey() + "\nAddress = 10.64.0.1/24\nListenPort = 51820\n\n" + peerBlock
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
