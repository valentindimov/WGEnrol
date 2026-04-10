package main

import (
	"errors"
	"fmt"
	"strings"

	"gopkg.in/ini.v1"
)

type WgPeer struct {
	Pubkey       string
	PresharedKey *string
	AllowedIps   string
	Comment      string
}

type WgConf struct {
	filePath string
	file     *ini.File
	peers    map[string]WgPeer
}

func loadWgConf(filePath string) (*WgConf, error) {
	// Step 1: Load INI file
	options := ini.LoadOptions{
		AllowNonUniqueSections:     true,
		AllowShadows:               true,
		AllowDuplicateShadowValues: true,
		AllowBooleanKeys:           true,
	}
	cfg, err := ini.LoadSources(options, filePath)
	if err != nil {
		return nil, err
	}
	interfaceSection := cfg.Section("Interface")
	if interfaceSection == nil {
		return nil, errors.New("No Interface section found in the file.")
	}
	interfaceSection.Comment = "# This file is managed automatically.\n# Do not edit it, your changes may get overwritten."

	// Step 2: load peers from file
	peersMap := make(map[string]WgPeer)
	sections, err := cfg.SectionsByName("Peer")
	if err == nil && sections != nil {
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
				allowedIPs := ""
				if section.HasKey("AllowedIPs") {
					val, err = section.GetKey("AllowedIPs")
					if err != nil {
						return nil, err
					}
					allowedIPs = strings.TrimSpace(val.Value())
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
				peersMap[pubkey] = WgPeer{
					Pubkey:       pubkey,
					PresharedKey: presharedKey,
					AllowedIps:   allowedIPs,
					Comment:      comment,
				}
			}
		}
	}

	// Finally: Write back the file to ensure the warning is displayed, and return
	err = cfg.SaveTo(filePath)
	if err != nil {
		return nil, err
	}
	result := WgConf{
		filePath: filePath,
		file:     cfg,
		peers:    peersMap,
	}
	return &result, nil
}

func (wgConf *WgConf) save(applyTo *string) error {
	// Edit the INI file with the contents of the peers map
	wgConf.file.DeleteSection("Peer")
	for _, peer := range wgConf.peers {
		sec, err := wgConf.file.NewSection("Peer")
		if err != nil {
			return err
		}
		_, err = sec.NewKey("PublicKey", peer.Pubkey)
		if err != nil {
			return err
		}
		_, err = sec.NewKey("AllowedIPs", peer.AllowedIps)
		if err != nil {
			return err
		}
		if peer.PresharedKey != nil {
			_, err = sec.NewKey("PresharedKey", *peer.PresharedKey)
			if err != nil {
				return err
			}
		}
		sec.Comment = fmt.Sprintf("# %s", peer.Comment)
	}
	// Save the INI file
	err := wgConf.file.SaveTo(wgConf.filePath)
	if err != nil {
		return err
	}
	// If requested, apply the new configuration
	if applyTo != nil {
		// The below code is the equivalent of "/usr/bin/wg-quick strip ${filePath} | /usr/bin/wg syncconf ${applyTo} /dev/fd/0"
		/*
			stripCmd := exec.Command("/usr/bin/wg-quick", "strip", wgConf.filePath)
			stripCmdOut, err := stripCmd.StdoutPipe()
			if err != nil {
				return err
			}
			syncCmd := exec.Command("/usr/bin/wg", "syncconf", *applyTo, "/dev/fd/0")
			syncCmd.Stdin = stripCmdOut
			syncCmd.Start()
			stripCmd.Start()
			errSync := syncCmd.Wait()
			errStrip := stripCmd.Wait()
			if errStrip != nil {
				return errStrip
			}
			if errSync != nil {
				return errSync
			}
		*/
	}
	return nil
}
