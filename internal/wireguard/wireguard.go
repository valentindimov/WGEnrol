// Package wireguard holds the domain model (peers, pending enrollments, keys)
// and all direct WireGuard device interaction. The persistence contracts
// (PeerStore/SessionStore) live in internal/storage; the wireguard package
// never imports storage or server.
package wireguard

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// KeyLen is the length of a WireGuard key in bytes.
const KeyLen = wgtypes.KeyLen

// Key is a 32-byte WireGuard key: an X25519 public, private or preshared key.
// It is also used to identify pending enrollments, where it carries the
// SHA-256 digest of an enrollment token instead of a real public key.
type Key [KeyLen]byte

// DecodeWireguardKey parses a base64-encoded WireGuard key.
func DecodeWireguardKey(strKey string) (Key, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(strKey)
	if err != nil {
		return Key{}, err
	}
	return KeyFromBytes(keyBytes)
}

// KeyFromBytes converts a 32-byte slice into a Key.
func KeyFromBytes(keyBytes []byte) (Key, error) {
	if len(keyBytes) != KeyLen {
		return Key{}, fmt.Errorf("Wrong key length: should be %d, is %d", KeyLen, len(keyBytes))
	}
	return Key(keyBytes), nil
}

// String returns the key's base64 representation.
func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

type WgPeer struct {
	Pubkey       Key
	PresharedKey *Key
	AllowedIps   []netip.Prefix
	Comment      string
}

// PendingPeer is an outstanding invite: the holder of the enrollment token
// may claim it and register a real public key. The store receives only the
// token's SHA-256 digest (TokenHash), so a database leak cannot be used to
// forge enrollment links.
type PendingPeer struct {
	TokenHash  Key
	Comment    string
	AllowedIps []netip.Prefix
	CreatedAt  time.Time
}

// AllocateAllowedIPs picks one free host IP in each of the device's networks,
// avoiding IPs already reserved by real or pending peers. The device's own
// addresses are skipped implicitly: scanning starts one address after each
// prefix's address, which must therefore be the interface's own address (as
// returned by GetDeviceNets, whose prefixes carry the interface address).
// The returned prefixes are single-host routes.
func AllocateAllowedIPs(deviceNets []netip.Prefix, peers []WgPeer, pending []PendingPeer) ([]netip.Prefix, error) {
	deviceIPs := make([]netip.Addr, 0, len(deviceNets))
	for _, network := range deviceNets {
		deviceIPs = append(deviceIPs, network.Addr())
	}

	ips := make([]netip.Prefix, 0, len(deviceNets))
	for _, network := range deviceNets {
		freeIPFound := false
	ipSearchLoop:
		for ip := network.Addr().Next(); network.Contains(ip); ip = ip.Next() {
			if slices.Contains(deviceIPs, ip) {
				continue ipSearchLoop
			}
			for _, peer := range peers {
				for _, peerNet := range peer.AllowedIps {
					if peerNet.Contains(ip) {
						continue ipSearchLoop
					}
				}
			}
			for _, entry := range pending {
				for _, entryNet := range entry.AllowedIps {
					if entryNet.Contains(ip) {
						continue ipSearchLoop
					}
				}
			}
			ips = append(ips, netip.PrefixFrom(ip, ip.BitLen()))
			freeIPFound = true
			break ipSearchLoop
		}
		if !freeIPFound {
			return nil, fmt.Errorf("No free IP found for network %s", network.String())
		}
	}
	return ips, nil
}

func (peer WgPeer) allowedIpsAsNetList() []net.IPNet {
	result := make([]net.IPNet, 0, len(peer.AllowedIps))
	for _, prefix := range peer.AllowedIps {
		result = append(result, net.IPNet{
			IP:   prefix.Addr().AsSlice(),
			Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
		})
	}
	return result
}

// ApplyPeerConfig pushes the full peer list to the WireGuard device, replacing
// whatever peer list the device currently has. Pending enrollments are never
// part of the peer list; they exist only in the store.
func ApplyPeerConfig(ifname string, peers []WgPeer) error {
	wgClient, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wgClient.Close()

	newPeers := make([]wgtypes.PeerConfig, 0, len(peers))
	for _, peer := range peers {
		psk := wgtypes.Key{}
		if peer.PresharedKey != nil {
			psk = wgtypes.Key(*peer.PresharedKey)
		}
		newPeers = append(newPeers, wgtypes.PeerConfig{
			PublicKey:         wgtypes.Key(peer.Pubkey),
			PresharedKey:      &psk,
			ReplaceAllowedIPs: true,
			AllowedIPs:        peer.allowedIpsAsNetList(),
		})
	}
	return wgClient.ConfigureDevice(ifname, wgtypes.Config{
		ReplacePeers: true,
		Peers:        newPeers,
	})
}

// GetDevicePubkey returns the public key of the WireGuard interface in base64.
func GetDevicePubkey(ifname string) (string, error) {
	wgClient, err := wgctrl.New()
	if err != nil {
		return "", err
	}
	defer wgClient.Close()
	device, err := wgClient.Device(ifname)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(device.PublicKey[:]), nil
}

// netsFromAddrs classifies the addresses assigned to an interface into
// prefixes. The address part of each prefix is the interface's own address
// (not necessarily masked) — AllocateAllowedIPs relies on that. IPv6
// link-local addresses are ignored. Extracted as a pure function so the
// address-classification branches are unit-testable with synthetic
// net.Addr values.
func netsFromAddrs(ifaceAddrs []net.Addr) ([]netip.Prefix, error) {
	resultNets := make([]netip.Prefix, 0, len(ifaceAddrs))
	for _, addr := range ifaceAddrs {
		switch addrByType := addr.(type) {
		case *net.IPAddr:
			addrParsed, err := netip.ParseAddr(addrByType.String())
			if err != nil {
				return nil, err
			}
			// Make sure to ignore IPv6 link-local addresses here, too
			if addrParsed.Is4() || (!addrParsed.IsLinkLocalMulticast() && !addrParsed.IsLinkLocalUnicast()) {
				resultNets = append(resultNets, netip.PrefixFrom(addrParsed, addrParsed.BitLen()))
			}
		case *net.IPNet:
			prefix, err := netip.ParsePrefix(addrByType.String())
			if err != nil {
				return nil, err
			}
			// Make sure to ignore IPv6 link-local addresses here
			if prefix.Addr().Is4() || (!prefix.Addr().IsLinkLocalMulticast() && !prefix.Addr().IsLinkLocalUnicast()) {
				resultNets = append(resultNets, prefix)
			}
		}
	}
	return resultNets, nil
}

// GetDeviceNets returns the networks assigned to the WireGuard interface.
// IPv6 link-local addresses are ignored.
func GetDeviceNets(ifname string) ([]netip.Prefix, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Name != ifname {
			continue
		}
		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		return netsFromAddrs(ifaceAddrs)
	}
	return nil, errors.New("WireGuard interface not found: " + ifname)
}
