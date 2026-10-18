package wireguard

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// deviceControl is the gate for the kernel-dependent device tests. test.sh
// enables them (and exports the env var) when it runs inside its network
// namespace, where we hold mapped-root privileges and the kernel supports
// WireGuard interfaces. Package-local fixed interface names keep concurrent
// package test binaries from colliding in the shared namespace.
const deviceControlEnv = "WGENROL_TEST_WIREGUARD_DEVICE_CONTROL"
const deviceIfname = "wgenrol-test"

// deviceControl gates the device tests and reports the interface name to use.
func deviceControl(t *testing.T) string {
	ifname := deviceIfname
	if os.Getenv(deviceControlEnv) == "" {
		t.Skipf("%s is not set: skipping WireGuard device tests (enabled automatically by test.sh inside its network namespace)", deviceControlEnv)
	}
	return ifname
}

func runIP(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

func runWgOut(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("wg", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("wg %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// newDeviceIf creates a temporary WireGuard interface and registers its
// removal via t.Cleanup.
func newDeviceIf(t *testing.T, ifname string) {
	t.Helper()
	runIP(t, "link", "add", ifname, "type", "wireguard")
	t.Cleanup(func() { runIP(t, "link", "del", ifname) })
}

// wgDumpPeers parses `wg show <ifname> dump`: peer lines are
// "pubkey\tpsk\tendpoint\tallowed-ips\t...".
func wgDumpPeers(t *testing.T, ifname string) map[string][2]string {
	t.Helper()
	out := runWgOut(t, "show", ifname, "dump")
	peers := make(map[string][2]string)
	for _, line := range strings.Split(out, "\n")[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		peers[fields[0]] = [2]string{fields[1], fields[3]}
	}
	return peers
}

// ApplyPeerConfig must push the full peer list to a real device, including
// PSKs and AllowedIPs, with ReplacePeers semantics.
func TestApplyPeerConfigDevice(t *testing.T) {
	ifname := deviceControl(t)
	newDeviceIf(t, ifname)

	psk := makeKey(t)
	peerA := WgPeer{Pubkey: makeKey(t), PresharedKey: &psk, AllowedIps: prefixes("10.198.0.2/32", "fd42:aaaa::2/128")}
	peerB := WgPeer{Pubkey: makeKey(t), AllowedIps: prefixes("10.198.0.3/32")}
	if err := ApplyPeerConfig(ifname, []WgPeer{peerA, peerB}); err != nil {
		t.Fatal(err)
	}

	peers := wgDumpPeers(t, ifname)
	if len(peers) != 2 {
		t.Fatalf("expected 2 peers on the device, got %d: %v", len(peers), peers)
	}
	entry, ok := peers[peerA.Pubkey.String()]
	if !ok {
		t.Fatal("peer A missing from the device")
	}
	if entry[1] != strings.Join([]string{"10.198.0.2/32", "fd42:aaaa::2/128"}, ",") {
		t.Errorf("peer A allowed-ips wrong: %q", entry[1])
	}
	if entry[0] != psk.String() {
		t.Errorf("peer A preshared key wrong: %q", entry[0])
	}
	if _, ok := peers[peerB.Pubkey.String()]; !ok {
		t.Error("peer B missing from the device")
	}

	// ReplacePeers semantics: re-applying a shorter list must drop peers.
	if err := ApplyPeerConfig(ifname, []WgPeer{peerA}); err != nil {
		t.Fatal(err)
	}
	peers = wgDumpPeers(t, ifname)
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer after replacement, got %d", len(peers))
	}
	if entry, ok := peers[peerA.Pubkey.String()]; !ok || entry[0] != psk.String() {
		t.Fatalf("peer A missing or changed after replacement: %v", peers)
	}
}

// GetDevicePubkey must agree with the wg tool's view of the same device (and
// must not return an unset key).
func TestGetDevicePubkeyDevice(t *testing.T) {
	ifname := deviceControl(t)
	newDeviceIf(t, ifname)

	priv := makeKey(t)
	keyFile := filepath.Join(t.TempDir(), "privkey")
	if err := os.WriteFile(keyFile, []byte(priv.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runWgOut(t, "set", ifname, "private-key", keyFile)

	got, err := GetDevicePubkey(ifname)
	if err != nil {
		t.Fatal(err)
	}
	if got == "" || got == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
		t.Fatalf("device public key unset/placeholder: %q", got)
	}
	want := runWgOut(t, "show", ifname, "public-key")
	if got != want {
		t.Fatalf("GetDevicePubkey %q disagrees with wg show %q", got, want)
	}
}

// GetDeviceNets must report the interface's own addresses as prefixes, with
// the address part carrying the host address (not masked).
func TestGetDeviceNetsDevice(t *testing.T) {
	ifname := deviceControl(t)
	newDeviceIf(t, ifname)
	runIP(t, "addr", "add", "10.199.0.1/24", "dev", ifname)
	runIP(t, "link", "set", ifname, "up")
	runIP(t, "addr", "add", "fd42::1/64", "dev", ifname)

	nets, err := GetDeviceNets(ifname)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(nets))
	for _, n := range nets {
		got = append(got, n.String())
	}
	slices.Sort(got)
	want := []string{"10.199.0.1/24", "fd42::1/64"}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("device networks %v, want %v", got, want)
	}
}
