package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/ini.v1"
)

type WgPeer struct {
	Pubkey       string
	PresharedKey *string
	AllowedIps   []netip.Prefix
	Comment      string
}

type WgConf struct {
	filePath     string
	file         *ini.File
	Peers        map[string]WgPeer
	VpnNetworks  []netip.Prefix
	InterfaceIPs []netip.Addr
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
	networksList := make([]netip.Prefix, 0)
	ipsList := make([]netip.Addr, 0)
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
			network, err := netip.ParsePrefix(strings.Trim(addr, " "))
			if err != nil {
				return nil, err
			}
			networksList = append(networksList, network.Masked())
			ipsList = append(ipsList, network.Addr())
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
				allowedIPs := make([]netip.Prefix, 0)
				for addr := range allowedIPsStrList {
					network, err := netip.ParsePrefix(strings.Trim(addr, " "))
					if err != nil {
						return nil, err
					}
					allowedIPs = append(allowedIPs, network.Masked())
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

func decodeKey(strKey string) (*[wgtypes.KeyLen]byte, error) {
	// FIXME: We should store this as a byte string to begin with...
	keySlice, err := base64.StdEncoding.DecodeString(strKey)
	if err != nil {
		return nil, err
	}
	if len(keySlice) != wgtypes.KeyLen {
		return nil, fmt.Errorf("Wrong key length: should be %d, is %d", wgtypes.KeyLen, len(keySlice))
	}
	result := [wgtypes.KeyLen]byte(keySlice)
	return &result, nil
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

func (ctx *ServerContext) applyDeviceConfig() error {
	wgClient, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wgClient.Close()
	newPeers := make([]wgtypes.PeerConfig, 0, len(ctx.ConfFile.Peers))
	for _, peer := range ctx.ConfFile.Peers {
		pubkey, err := decodeKey(peer.Pubkey)
		if err != nil {
			return err
		}
		var psk wgtypes.Key
		if peer.PresharedKey != nil {
			parsedPsk, err := decodeKey(*peer.PresharedKey)
			if err != nil {
				return err
			}
			psk = *parsedPsk
		}
		var thirtySeconds time.Duration
		thirtySeconds = 30 * 1000 * 1000 * 1000
		newPeers = append(newPeers, wgtypes.PeerConfig{
			PublicKey:                   *pubkey,
			PresharedKey:                &psk,
			PersistentKeepaliveInterval: &thirtySeconds,
			ReplaceAllowedIPs:           true,
			AllowedIPs:                  peer.allowedIpsAsNetList(),
		})
	}
	if err := wgClient.ConfigureDevice(*ctx.Config.Wireguard.Ifname, wgtypes.Config{
		ReplacePeers: true,
		Peers:        newPeers,
	}); err != nil {
		return err
	}
	return nil
}

func (ctx *ServerContext) Commit() error {
	// Edit the INI file with the contents of the peers map
	ctx.ConfFile.file.DeleteSection("Peer")
	for _, peer := range ctx.ConfFile.Peers {
		sec, err := ctx.ConfFile.file.NewSection("Peer")
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
	err := atomicSaveIniFile(ctx.ConfFile.file, ctx.ConfFile.filePath)
	if err != nil {
		return err
	}
	// If requested, apply the new configuration and return
	return ctx.applyDeviceConfig()
}

func (wgConf *WgConf) GetAllowedIPs() ([]netip.Prefix, error) {
	ips := make([]netip.Prefix, 0, len(wgConf.VpnNetworks))
	for _, network := range wgConf.VpnNetworks {
		network, _ := netip.ParsePrefix(network.String())
		freeIPFound := false
	ipSearchLoop:
		for ip := network.Addr().Next(); network.Contains(ip); ip = ip.Next() {
			if slices.Contains(wgConf.InterfaceIPs, ip) {
				continue ipSearchLoop
			}
			for _, peer := range wgConf.Peers {
				for _, peerNet := range peer.AllowedIps {
					if peerNet.Contains(ip) {
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

func (ctx *ServerContext) GetDevicePubkey() (*string, error) {
	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer wgClient.Close()
	device, err := wgClient.Device(*ctx.Config.Wireguard.Ifname)
	if err != nil {
		return nil, err
	}
	result := base64.StdEncoding.EncodeToString(device.PublicKey[:])
	return &result, nil
}
