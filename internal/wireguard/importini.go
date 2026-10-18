package wireguard

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"gopkg.in/ini.v1"
)

// ImportPeersFromINI reads a wg-quick style WireGuard configuration file and
// returns the peers defined in it. The [Interface] section must exist but is
// otherwise ignored. A peer's name is taken from a comment preceding the
// [Peer] section header; comments inside the section are ignored (this matches
// the historical behavior of the file-based store it replaces).
func ImportPeersFromINI(path string) ([]WgPeer, error) {
	options := ini.LoadOptions{
		AllowNonUniqueSections:     true,
		AllowShadows:               true,
		AllowDuplicateShadowValues: true,
		AllowBooleanKeys:           true,
	}
	cfg, err := ini.LoadSources(options, path)
	if err != nil {
		return nil, err
	}
	if _, err := cfg.GetSection("Interface"); err != nil {
		// GetSection errors if the section is missing (Section would auto-create it).
		return nil, errors.New("No Interface section found in the file.")
	}

	peers := make([]WgPeer, 0)
	sections, err := cfg.SectionsByName("Peer")
	if err != nil || sections == nil {
		return peers, nil
	}
	for _, section := range sections {
		if !section.HasKey("PublicKey") {
			// Peers without a public key are ignored
			continue
		}
		val, err := section.GetKey("PublicKey")
		if err != nil {
			return nil, err
		}
		pubkeyStr := val.Value()
		pubkey, err := DecodeWireguardKey(pubkeyStr)
		if err != nil {
			return nil, fmt.Errorf("Invalid peer %s: %s", pubkeyStr, err.Error())
		}

		// Extract comment, make sure to strip the leading comment characters
		comment := section.Comment
		if strings.HasPrefix(comment, "#") || strings.HasPrefix(comment, ";") {
			comment = comment[1:]
		}
		comment = strings.TrimSpace(comment)

		// Extract AllowedIPs. This can be missing, in which case it's an empty list.
		allowedIPsStr := ""
		if section.HasKey("AllowedIPs") {
			val, err = section.GetKey("AllowedIPs")
			if err != nil {
				return nil, err
			}
			allowedIPsStr = strings.TrimSpace(val.Value())
		}
		allowedIPs := make([]netip.Prefix, 0)
		for addr := range strings.SplitSeq(allowedIPsStr, ",") {
			addr = strings.Trim(addr, " ")
			if len(addr) == 0 {
				continue
			}
			network, err := netip.ParsePrefix(addr)
			if err != nil {
				return nil, err
			}
			allowedIPs = append(allowedIPs, network.Masked())
		}
		if len(allowedIPs) <= 0 {
			return nil, fmt.Errorf("Invalid peer %s: %s", pubkeyStr, "AllowedIPs cannot be empty.")
		}

		// If the peer has a PresharedKey, read that too
		var presharedKey *Key
		if section.HasKey("PresharedKey") {
			val, err = section.GetKey("PresharedKey")
			if err != nil {
				return nil, err
			}
			pskStr := strings.TrimSpace(val.Value())
			psk, err := DecodeWireguardKey(pskStr)
			if err != nil {
				return nil, fmt.Errorf("Invalid peer %s: %s", pubkeyStr, err.Error())
			}
			presharedKey = &psk
		}

		peers = append(peers, WgPeer{
			Pubkey:       pubkey,
			PresharedKey: presharedKey,
			AllowedIps:   allowedIPs,
			Comment:      comment,
		})
	}
	return peers, nil
}
