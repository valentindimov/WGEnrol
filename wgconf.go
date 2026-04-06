package main

import (
	"fmt"
	"strings"

	"gopkg.in/ini.v1"
)

type WgPeer struct {
	pubkey       string
	presharedKey *string
	allowedIps   []string
	comment      string
}

func loadWgConf(path string) (*ini.File, error) {
	options := ini.LoadOptions{
		AllowNonUniqueSections:     true,
		AllowShadows:               true,
		AllowDuplicateShadowValues: true,
		AllowBooleanKeys:           true,
	}
	cfg, err := ini.LoadSources(options, "test.ini")
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func saveWgConf(wgConf *ini.File, path string) {
	wgConf.SaveTo(path)
}

func getPeers(wgConf *ini.File) (map[string]WgPeer, error) {
	sections, err := wgConf.SectionsByName("Peer")
	if err != nil {
		return nil, err
	}
	result := make(map[string]WgPeer)
	for _, section := range sections {
		if section.HasKey("PublicKey") {
			// Extract public key (all peers without one are ignored)
			val, err := section.GetKey("PublicKey")
			if err != nil {
				return nil, err
			}
			pubkey := val.Value()
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
			allowedIPs := strings.Split(allowedIPsStr, ",")
			for index, ipStr := range allowedIPs {
				allowedIPs[index] = strings.TrimSpace(ipStr)
			}
			// If the peer has a PresharedKey, read that too
			var presharedKey *string
			if section.HasKey("PresharedKey") {
				val, err = section.GetKey("PresharedKey")
				if err != nil {
					return nil, err
				}
				psk := strings.TrimSpace(val.Value())
				presharedKey = &psk
			}

			// Construct the peer object
			result[pubkey] = WgPeer{
				pubkey:       pubkey,
				presharedKey: presharedKey,
				allowedIps:   allowedIPs,
				comment:      comment,
			}
		}
	}
	return result, nil
}

func setPeers(wgConf *ini.File, peers map[string]WgPeer) error {
	wgConf.DeleteSection("Peer")
	for _, peer := range peers {
		sec, err := wgConf.NewSection("Peer")
		if err != nil {
			return err
		}
		_, err = sec.NewKey("PublicKey", peer.pubkey)
		if err != nil {
			return err
		}
		_, err = sec.NewKey("AllowedIPs", strings.Join(peer.allowedIps, ","))
		if err != nil {
			return err
		}
		if peer.presharedKey != nil {
			_, err = sec.NewKey("PresharedKey", *peer.presharedKey)
			if err != nil {
				return err
			}
		}
		sec.Comment = fmt.Sprintf("# %s", peer.comment)
	}
	return nil
}
