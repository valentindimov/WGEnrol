package wireguard

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
	filePath string
	file     *ini.File
	Peers    map[string]WgPeer
	ifname   string
}

func (peer *WgPeer) Validate() error {
	_, err := DecodeWireguardKey(peer.Pubkey)
	if err != nil {
		return err
	}
	if peer.PresharedKey != nil {
		_, err = DecodeWireguardKey(*peer.PresharedKey)
		if err != nil {
			return err
		}
	}
	if len(peer.AllowedIps) <= 0 {
		return fmt.Errorf("AllowedIPs cannot be empty.")
	}
	return nil
}

func LoadWgConf(filePathIn string, ifname string) (*WgConf, error) {
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
				peer := WgPeer{
					Pubkey:       pubkey,
					PresharedKey: presharedKey,
					AllowedIps:   allowedIPs,
					Comment:      comment,
				}
				if err := peer.Validate(); err != nil {
					return nil, fmt.Errorf("Invalid peer %s: %s", peer.Pubkey, err.Error())
				}
				// Construct the peer object
				peersMap[pubkey] = peer
			}
		}
	}

	// Finally: Write back the file to ensure the warning is displayed, and return
	err = atomicSaveIniFile(cfg, filePathAbs)
	if err != nil {
		return nil, err
	}
	result := WgConf{
		filePath: filePathAbs,
		file:     cfg,
		Peers:    peersMap,
	}
	return &result, nil
}

func atomicSaveIniFile(iniFile *ini.File, toPath string) error {
	toPath, err := filepath.Abs(toPath)
	if err != nil {
		return err
	}
	tempDir := filepath.Dir(toPath)
	tempfile, err := os.CreateTemp(tempDir, fmt.Sprintf("%s.swp", filepath.Base(toPath)))
	if err != nil {
		return err
	}
	defer os.Remove(tempfile.Name())
	err = iniFile.SaveTo(tempfile.Name())
	if err != nil {
		return err
	}
	err = tempfile.Sync()
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
	// Try to fsync the directory as well, but treat it as best-effort (e.g. on Windows this isn't supported, and we can't undo at this point anyway)
	dir, err := os.Open(tempDir)
	if err == nil {
		dir.Sync()
		dir.Close()
	}
	return nil
}

func DecodeWireguardKey(strKey string) (*[wgtypes.KeyLen]byte, error) {
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

func (ctx *WgConf) ApplyDeviceConfig() error {
	wgClient, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wgClient.Close()
	newPeers := make([]wgtypes.PeerConfig, 0, len(ctx.Peers))
	for _, peer := range ctx.Peers {
		pubkey, err := DecodeWireguardKey(peer.Pubkey)
		if err != nil {
			return err
		}
		var psk wgtypes.Key
		if peer.PresharedKey != nil {
			parsedPsk, err := DecodeWireguardKey(*peer.PresharedKey)
			if err != nil {
				return err
			}
			psk = *parsedPsk
		}

		newPeers = append(newPeers, wgtypes.PeerConfig{
			PublicKey:         *pubkey,
			PresharedKey:      &psk,
			ReplaceAllowedIPs: true,
			AllowedIPs:        peer.allowedIpsAsNetList(),
		})
	}
	if err := wgClient.ConfigureDevice(ctx.ifname, wgtypes.Config{
		ReplacePeers: true,
		Peers:        newPeers,
	}); err != nil {
		return err
	}
	return nil
}

func (ctx *WgConf) Commit() error {
	// Edit the INI file with the contents of the peers map
	ctx.file.DeleteSection("Peer")
	for _, peer := range ctx.Peers {
		sec, err := ctx.file.NewSection("Peer")
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
	// If requested, apply the new configuration
	err := ctx.ApplyDeviceConfig()
	if err != nil {
		return err
	}
	// If the apply was successful, save the INI file.
	// FIXME: The transaction / failure handling could be better here, but I'll be rewriting the backing store anyway, so this is fine for now.
	return atomicSaveIniFile(ctx.file, ctx.filePath)
}

func (ctx *WgConf) FindSuitableAllowedIPs() ([]netip.Prefix, error) {
	deviceNets, err := ctx.GetDeviceNets()
	if err != nil {
		return nil, err
	}

	deviceIPs := make([]netip.Addr, 0, len(*deviceNets))
	for _, network := range *deviceNets {
		deviceIPs = append(deviceIPs, network.Addr())
	}

	ips := make([]netip.Prefix, 0, len(*deviceNets))
	for _, network := range *deviceNets {
		network, _ := netip.ParsePrefix(network.String())
		freeIPFound := false
	ipSearchLoop:
		for ip := network.Addr().Next(); network.Contains(ip); ip = ip.Next() {
			if slices.Contains(deviceIPs, ip) {
				continue ipSearchLoop
			}
			for _, peer := range ctx.Peers {
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

func (ctx *WgConf) GetDevicePubkey() (*string, error) {
	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer wgClient.Close()
	device, err := wgClient.Device(ctx.ifname)
	if err != nil {
		return nil, err
	}
	result := base64.StdEncoding.EncodeToString(device.PublicKey[:])
	return &result, nil
}

func (ctx *WgConf) GetDeviceNets() (*[]netip.Prefix, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Name == ctx.ifname {
			resultNets := make([]netip.Prefix, 0, len(ifaces))
			ifaceAddrs, err := iface.Addrs()
			if err != nil {
				return nil, err
			}
			for _, addr := range ifaceAddrs {
				switch addrByType := addr.(type) {
				case *net.IPAddr:
					addrParsed, err := netip.ParseAddr(addrByType.String())
					if err != nil {
						return nil, err
					}
					prefix := netip.PrefixFrom(addrParsed, addrParsed.BitLen())
					resultNets = append(resultNets, prefix)
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
			return &resultNets, nil
		}
	}
	return nil, fmt.Errorf("Interface %s not found.", ctx.ifname)
}
