package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/ini.v1"
)

type WgPeer struct {
	Pubkey       string
	PresharedKey *string
	AllowedIps   []*net.IPNet
	Comment      string
}

func (peer *WgPeer) toDTO() *WgPeerDTO {
	allowedIPsStrList := make([]string, 0, len(peer.AllowedIps))
	for _, network := range peer.AllowedIps {
		allowedIPsStrList = append(allowedIPsStrList, network.String())
	}
	return &WgPeerDTO{
		Pubkey:       peer.Pubkey,
		PresharedKey: peer.PresharedKey,
		AllowedIps:   allowedIPsStrList,
		Comment:      peer.Comment,
	}
}

type WgConf struct {
	filePath     string
	file         *ini.File
	Peers        map[string]WgPeer
	VpnNetworks  []*net.IPNet
	InterfaceIPs []net.IP
}

func validateWireguardKey(input string) error {
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return err
	}
	if len(decoded) != 32 {
		return fmt.Errorf("Invalid key: expected 32 bytes long, got %d bytes long.", len(decoded))
	}
	return nil
}

func (peer *WgPeer) validate() error {
	err := validateWireguardKey(peer.Pubkey)
	if err != nil {
		return err
	}
	if peer.PresharedKey != nil {
		err = validateWireguardKey(*peer.PresharedKey)
		if err != nil {
			return err
		}
	}
	if len(peer.AllowedIps) <= 0 {
		return fmt.Errorf("AllowedIPs cannot be empty.")
	}
	return nil
}

func loadWgConf(filePathIn string) (*WgConf, error) {
	// Step 1: Load INI file
	options := ini.LoadOptions{
		AllowNonUniqueSections:     true,
		AllowShadows:               true,
		AllowDuplicateShadowValues: true,
		AllowBooleanKeys:           true,
	}
	filePathAbs, err := filepath.Abs(filePathIn)
	if err != nil {
		return nil, err
	}
	cfg, err := ini.LoadSources(options, filePathAbs)
	if err != nil {
		return nil, err
	}
	interfaceSection := cfg.Section("Interface")
	if interfaceSection == nil {
		return nil, errors.New("No Interface section found in the file.")
	}
	interfaceSection.Comment = "# This file is managed automatically.\n# Do not edit it, your changes may get overwritten."

	// Step 2: Determine VPN networks
	networksList := make([]*net.IPNet, 0)
	ipsList := make([]net.IP, 0)
	if interfaceSection.HasKey("Address") {
		val, err := interfaceSection.GetKey("Address")
		if err != nil {
			return nil, err
		}
		networksStr := strings.Trim(val.Value(), " ")
		if len(networksStr) == 0 {
			return nil, fmt.Errorf("Address key in Interface section cannot be empty.")
		}
		addrs := strings.SplitSeq(networksStr, ",")
		for addr := range addrs {
			ip, network, err := net.ParseCIDR(strings.Trim(addr, " "))
			if err != nil {
				return nil, err
			}
			networksList = append(networksList, network)
			ipsList = append(ipsList, ip)
		}
	} else {
		return nil, fmt.Errorf("Could not find Address key in Interface section.")
	}

	// Step 3: load peers from file
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
				allowedIPsStr := ""
				if section.HasKey("AllowedIPs") {
					val, err = section.GetKey("AllowedIPs")
					if err != nil {
						return nil, err
					}
					allowedIPsStr = strings.TrimSpace(val.Value())
				}
				allowedIPsStrList := strings.SplitSeq(allowedIPsStr, ",")
				allowedIPs := make([]*net.IPNet, 0)
				for addr := range allowedIPsStrList {
					_, network, err := net.ParseCIDR(strings.Trim(addr, " "))
					if err != nil {
						return nil, err
					}
					allowedIPs = append(allowedIPs, network)
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
	err = atomicSaveIniFile(cfg, filePathAbs)
	if err != nil {
		return nil, err
	}
	result := WgConf{
		filePath:     filePathAbs,
		file:         cfg,
		Peers:        peersMap,
		VpnNetworks:  networksList,
		InterfaceIPs: ipsList,
	}
	return &result, nil
}

func atomicSaveIniFile(iniFile *ini.File, toPath string) error {
	toPath, err := filepath.Abs(toPath)
	if err != nil {
		return err
	}
	tempfile, err := os.CreateTemp(filepath.Dir(toPath), fmt.Sprintf("%s.swp", filepath.Base(toPath)))
	defer os.Remove(tempfile.Name())
	err = iniFile.SaveTo(tempfile.Name())
	if err != nil {
		return err
	}
	err = tempfile.Close()
	if err != nil {
		return err
	}
	err = os.Rename(tempfile.Name(), toPath)
	if err != nil {
		return err
	}
	return nil
}

func (wgConf *WgConf) save(applyTo *string) error {
	// Edit the INI file with the contents of the peers map
	wgConf.file.DeleteSection("Peer")
	for _, peer := range wgConf.Peers {
		sec, err := wgConf.file.NewSection("Peer")
		if err != nil {
			return err
		}
		_, err = sec.NewKey("PublicKey", peer.Pubkey)
		if err != nil {
			return err
		}
		allowedIPsStrList := make([]string, 0, len(peer.AllowedIps))
		for _, network := range peer.AllowedIps {
			allowedIPsStrList = append(allowedIPsStrList, network.String())
		}
		_, err = sec.NewKey("AllowedIPs", strings.Join(allowedIPsStrList, ","))
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
	// Save the INI file.
	err := atomicSaveIniFile(wgConf.file, wgConf.filePath)
	if err != nil {
		return err
	}
	// If requested, apply the new configuration
	if applyTo != nil {
		// The below code is the equivalent of "/usr/bin/wg-quick strip ${filePath} | /usr/bin/wg syncconf ${applyTo} /dev/fd/0"
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
	}
	return nil
}
