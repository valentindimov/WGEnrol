package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"testing"
)

// computeClientConfigAllowedIPs builds the client's Address from the
// intersection of the peer's allowed IPs and the device's own subnets.
func TestComputeClientConfigAllowedIPs(t *testing.T) {
	cases := []struct {
		name     string
		peerIPs  []string
		devNets  []string
		expected string
		wantErr  bool
	}{
		{"v4 dual-subnet", []string{"10.64.0.2/32", "10.64.1.2/32"}, []string{"10.64.0.1/24", "10.64.1.1/24"}, "10.64.0.2/24,10.64.1.2/24", false},
		{"single subnet", []string{"10.64.0.5/32"}, []string{"10.64.0.1/24"}, "10.64.0.5/24", false},
		{"ipv6", []string{"fd00::2/128"}, []string{"fd00::1/64"}, "fd00::2/64", false},
		{"empty intersection errors", []string{"192.168.99.5/32"}, []string{"10.64.0.1/24"}, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dev := prefixes(c.devNets...)
			got, err := computeClientConfigAllowedIPs(prefixes(c.peerIPs...), &dev)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", *got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if *got != c.expected {
				t.Errorf("got %q, want %q", *got, c.expected)
			}
		})
	}
}

func TestGetFirstIPInNetwork(t *testing.T) {
	cases := []struct{ in, want string }{
		{"10.64.0.2/32", "10.64.0.2"}, // host route -> itself
		{"10.64.0.0/24", "10.64.0.1"}, // subnet -> first host (skips network addr)
		{"fd00::/64", "fd00::1"},      // ipv6 subnet -> first host
		{"fd00::5/128", "fd00::5"},    // ipv6 host route -> itself
	}
	for _, c := range cases {
		if got := getFirstIPInNetwork(netip.MustParsePrefix(c.in)); got.String() != c.want {
			t.Errorf("getFirstIPInNetwork(%s) = %s, want %s", c.in, got, c.want)
		}
	}
}

// handleCreatePeer must reject UserEmail values containing CRLF (SMTP header
// injection) before any mail is sent. The email check runs before fromDTO, so
// no live WireGuard device is needed.
func TestCreatePeerRejectsEmailInjection(t *testing.T) {
	payloads := []string{
		"a@b.com\r\nBcc: attacker@y.com",
		"a@b.com\nBcc: attacker@y.com",
		"a@b.com\r\nSubject: hijacked",
		"not-an-email",
	}
	for _, email := range payloads {
		ctx := &ServerContext{Config: &WgEnrolConfig{}}
		body, _ := json.Marshal(map[string]any{
			"Peer":             map[string]any{"Pubkey": validKey(), "Comment": "x"},
			"UserEmail":        email,
			"RegistrationLink": "http://example/",
		})
		req := httptest.NewRequest("POST", "/peer", bytes.NewReader(body))
		_, herr := handleCreatePeer(ctx, req, httptest.NewRecorder())
		if herr == nil || herr.status != 400 {
			t.Errorf("email %q: expected 400, got %v", email, herr)
		}
	}
}
