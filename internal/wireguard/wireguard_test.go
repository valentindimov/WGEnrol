package wireguard

import (
	"encoding/base64"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestDecodeWireguardKey(t *testing.T) {
	key := makeKey(t)
	decoded, err := DecodeWireguardKey(key.String())
	if err != nil || decoded != key {
		t.Fatalf("valid key rejected or mismatched: %v", err)
	}
	if _, err := DecodeWireguardKey("not!base64!"); err == nil {
		t.Fatal("expected error for non-base64 key")
	}
	if _, err := DecodeWireguardKey(base64.StdEncoding.EncodeToString(make([]byte, 16))); err == nil {
		t.Fatal("expected error for wrong-length key")
	}
}

func TestKeyFromBytes(t *testing.T) {
	if _, err := KeyFromBytes(make([]byte, 32)); err != nil {
		t.Fatalf("32 bytes rejected: %v", err)
	}
	if _, err := KeyFromBytes(make([]byte, 31)); err == nil {
		t.Fatal("expected error for 31 bytes")
	}
}

func TestKeyStringRoundTrip(t *testing.T) {
	key := makeKey(t)
	decoded, err := DecodeWireguardKey(key.String())
	if err != nil || decoded != key {
		t.Fatalf("String() -> DecodeWireguardKey round trip failed: %v", err)
	}
}

func TestAllocateAllowedIPs(t *testing.T) {
	cases := []struct {
		name     string
		device   []string
		peers    [][]string
		pending  [][]string
		expected []string
		wantErr  bool
	}{
		{
			name:     "starts after the device's own address",
			device:   []string{"10.64.0.1/24"},
			expected: []string{"10.64.0.2/32"},
		},
		{
			name:     "addresses below the device address are never used",
			device:   []string{"10.64.0.5/24"},
			expected: []string{"10.64.0.6/32"},
		},
		{
			name:     "skips peer reservations",
			device:   []string{"10.64.0.1/24"},
			peers:    [][]string{{"10.64.0.2/32"}},
			expected: []string{"10.64.0.3/32"},
		},
		{
			name:     "skips pending reservations",
			device:   []string{"10.64.0.1/24"},
			pending:  [][]string{{"10.64.0.2/32"}},
			expected: []string{"10.64.0.3/32"},
		},
		{
			name:     "one address per device network",
			device:   []string{"10.64.0.1/24", "10.65.0.1/24"},
			expected: []string{"10.64.0.2/32", "10.65.0.2/32"},
		},
		{
			name:     "ipv6",
			device:   []string{"fd00::1/64"},
			expected: []string{"fd00::2/128"},
		},
		{
			name:    "exhausted network",
			device:  []string{"10.64.0.1/32"},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			deviceNets := prefixes(c.device...)
			peers := make([]WgPeer, 0)
			for _, peerIPs := range c.peers {
				peers = append(peers, WgPeer{AllowedIps: prefixes(peerIPs...)})
			}
			pending := make([]PendingPeer, 0)
			for _, pendingIPs := range c.pending {
				pending = append(pending, PendingPeer{AllowedIps: prefixes(pendingIPs...)})
			}
			got, err := AllocateAllowedIPs(deviceNets, peers, pending)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(c.expected) {
				t.Fatalf("expected %d prefixes, got %d: %v", len(c.expected), len(got), got)
			}
			for i, prefix := range got {
				if prefix.String() != c.expected[i] {
					t.Errorf("position %d: expected %s, got %s", i, c.expected[i], prefix.String())
				}
			}
		})
	}
}

func TestAllowedIpsAsNetList(t *testing.T) {
	peer := WgPeer{AllowedIps: prefixes("10.64.0.2/32", "fd00::2/128")}
	nets := peer.allowedIpsAsNetList()
	if len(nets) != 2 || nets[0].String() != "10.64.0.2/32" || nets[1].String() != "fd00::2/128" {
		t.Fatalf("unexpected net list: %+v", nets)
	}
}

func TestImportINIValidPeer(t *testing.T) {
	p := writeConf(t, "# Alice\n[Peer]\nPublicKey = "+makeKey(t).String()+"\nAllowedIPs = 10.64.0.2/32\n")
	peers, err := ImportPeersFromINI(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0].Comment != "Alice" {
		t.Errorf("expected name 'Alice', got %q", peers[0].Comment)
	}
	if len(peers[0].AllowedIps) != 1 || peers[0].AllowedIps[0].String() != "10.64.0.2/32" {
		t.Errorf("unexpected allowed IPs: %v", peers[0].AllowedIps)
	}
	if peers[0].PresharedKey != nil {
		t.Errorf("expected no preshared key, got one")
	}
}

func TestImportINIPresharedKey(t *testing.T) {
	psk := makeKey(t)
	p := writeConf(t, "# Alice\n[Peer]\nPublicKey = "+makeKey(t).String()+"\nAllowedIPs = 10.64.0.2/32\nPresharedKey = "+psk.String()+"\n")
	peers, err := ImportPeersFromINI(p)
	if err != nil {
		t.Fatal(err)
	}
	if peers[0].PresharedKey == nil || *peers[0].PresharedKey != psk {
		t.Fatalf("expected preshared key %s, got %v", psk.String(), peers[0].PresharedKey)
	}
}

func TestImportINIRejectsInvalidKey(t *testing.T) {
	p := writeConf(t, "# bad\n[Peer]\nPublicKey = THIS-IS-NOT-A-VALID-KEY\nAllowedIPs = 10.64.0.2/32\n")
	if _, err := ImportPeersFromINI(p); err == nil || !strings.Contains(err.Error(), "Invalid peer") {
		t.Fatalf("expected 'Invalid peer' error, got: %v", err)
	}
}

func TestImportINIRejectsMissingAllowedIPs(t *testing.T) {
	p := writeConf(t, "# no allowed ips\n[Peer]\nPublicKey = "+makeKey(t).String()+"\n")
	if _, err := ImportPeersFromINI(p); err == nil || !strings.Contains(err.Error(), "AllowedIPs cannot be empty") {
		t.Fatalf("expected clean AllowedIPs error, got: %v", err)
	}
}

func TestImportINIToleratesTrailingComma(t *testing.T) {
	p := writeConf(t, "# Alice\n[Peer]\nPublicKey = "+makeKey(t).String()+"\nAllowedIPs = 10.64.0.2/32, 10.64.1.2/32,\n")
	peers, err := ImportPeersFromINI(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(peers[0].AllowedIps) != 2 {
		t.Fatalf("expected 2 allowed IPs, got %d", len(peers[0].AllowedIps))
	}
}

// Documents an accepted limitation: a name comment placed INSIDE the [Peer]
// section (the wg-quick convention) is not read as the peer name; only a
// comment preceding the section header is. Change this consciously if ever
// supporting in-section names.
func TestImportINIInSectionCommentNotRead(t *testing.T) {
	p := writeConf(t, "[Peer]\n# Alice\nPublicKey = "+makeKey(t).String()+"\nAllowedIPs = 10.64.0.2/32\n")
	peers, err := ImportPeersFromINI(p)
	if err != nil {
		t.Fatal(err)
	}
	if peers[0].Comment != "" {
		t.Errorf("expected in-section comment to be unread, got %q", peers[0].Comment)
	}
}

func TestImportINIRequiresInterfaceSection(t *testing.T) {
	p := filepath.Join(t.TempDir(), "wg.conf")
	if err := os.WriteFile(p, []byte("[Peer]\nPublicKey = x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportPeersFromINI(p); err == nil || !strings.Contains(err.Error(), "No Interface section") {
		t.Fatalf("expected 'No Interface section' error, got: %v", err)
	}
}

func TestImportINIRejectsInvalidPresharedKey(t *testing.T) {
	p := writeConf(t, "# Bad PSK\n[Peer]\nPublicKey = "+makeKey(t).String()+"\nAllowedIPs = 10.64.0.2/32\nPresharedKey = not!base64!\n")
	if _, err := ImportPeersFromINI(p); err == nil || !strings.Contains(err.Error(), "Invalid peer") {
		t.Fatalf("expected 'Invalid peer' error, got: %v", err)
	}
}

const nonexistentIfname = "wgenrol-test-nonexistent-iface"

// netsFromAddrs classifies interface addresses: IPv4 and global-IPv6 entries
// become prefixes (address kept, possibly unmasked), IPv6 link-local
// addresses are dropped, and unparseable entries fail with an error.
func TestNetsFromAddrs(t *testing.T) {
	ipNet := func(s string) *net.IPNet {
		prefix := netip.MustParsePrefix(s)
		return &net.IPNet{
			IP:   prefix.Addr().AsSlice(),
			Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
		}
	}
	cases := []struct {
		name     string
		in       []net.Addr
		expected []string // nil expects an error
		wantErr  bool
	}{
		{"ipv4 subnet with host address", []net.Addr{ipNet("10.64.0.5/24")}, []string{"10.64.0.5/24"}, false},
		{"global ipv6", []net.Addr{ipNet("fd00::1/64")}, []string{"fd00::1/64"}, false},
		{"ipv6 link-local dropped", []net.Addr{ipNet("fe80::1/64")}, []string{}, false},
		{"ipv6 link-local multicast dropped", []net.Addr{ipNet("ff02::1/128")}, []string{}, false},
		{"ipv4 point-to-point addr", []net.Addr{&net.IPAddr{IP: net.ParseIP("10.64.0.7")}}, []string{"10.64.0.7/32"}, false},
		{"ipv6 addr", []net.Addr{&net.IPAddr{IP: net.ParseIP("fd00::5")}}, []string{"fd00::5/128"}, false},
		{"ipv6 link-local addr dropped", []net.Addr{&net.IPAddr{IP: net.ParseIP("fe80::9")}}, []string{}, false},
		{"mixed list", []net.Addr{ipNet("fe80::1/64"), ipNet("10.64.0.5/24"), &net.IPAddr{IP: net.ParseIP("fd00::5")}}, []string{"10.64.0.5/24", "fd00::5/128"}, false},
		{"unparseable entry", []net.Addr{&net.IPNet{}}, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			nets, err := netsFromAddrs(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %v", nets)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := make([]string, 0, len(nets))
			for _, n := range nets {
				got = append(got, n.String())
			}
			if !slices.Equal(got, c.expected) {
				t.Fatalf("expected %v, got %v", c.expected, got)
			}
		})
	}
}

// Without a kernel WireGuard interface of the given name, the device
// operations must fail cleanly (they are device-side happy paths only).
func TestApplyPeerConfigUnknownInterface(t *testing.T) {
	peer := WgPeer{Pubkey: makeKey(t), AllowedIps: prefixes("10.64.0.2/32")}
	if err := ApplyPeerConfig(nonexistentIfname, []WgPeer{peer}); err == nil {
		t.Fatal("expected an error for an unknown interface")
	}
}

func TestGetDevicePubkeyUnknownInterface(t *testing.T) {
	if _, err := GetDevicePubkey(nonexistentIfname); err == nil {
		t.Fatal("expected an error for an unknown interface")
	}
}

func TestGetDeviceNetsUnknownInterface(t *testing.T) {
	if _, err := GetDeviceNets(nonexistentIfname); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected a 'not found' error, got: %v", err)
	}
}

// A real interface (loopback) exercises the happy path of GetDeviceNets on
// Linux without a WireGuard module.
func TestGetDeviceNetsLoopback(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("GetDeviceNets happy path uses the loopback interface (Linux)")
	}
	nets, err := GetDeviceNets("lo")
	if err != nil {
		t.Fatalf("GetDeviceNets(lo) failed: %v", err)
	}
	found := false
	for _, n := range nets {
		if n.Contains(netip.MustParseAddr("127.0.0.1")) {
			found = true
		}
	}
	if !found {
		t.Fatalf("loopback networks do not include 127.0.0.1: %v", nets)
	}
}
