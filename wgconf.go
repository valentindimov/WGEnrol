package main

import (
	"fmt"

	"gopkg.in/ini.v1"
)

type WgPeer struct {
	pubkey string
	// presharedKey string
	allowedIps []string
	comment    string
} // map[string]WgPeer

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

func findPeerIndexByPubKey(wgConf *ini.File, pubKey string) (int, bool) {
	sections, err := wgConf.SectionsByName("Peer")
	if err != nil {
		return 0, false
	}
	for index, section := range sections {
		if section.HasKey("PublicKey") {
			val, err := section.GetKey("PublicKey")
			if err != nil {
				return 0, false
			}
			if val.Value() == pubKey {
				return index, true
			}
		}
	}
	return 0, false
}

func deletePeerByPubKey(wgConf *ini.File, pubKey string) error {
	for index, found := findPeerIndexByPubKey(wgConf, pubKey); found == true; index, found = findPeerIndexByPubKey(wgConf, pubKey) {
		err := wgConf.DeleteSectionWithIndex("Peer", index)
		if err != nil {
			return err
		}
	}
	return nil
}

func addOrReplacePeer(wgConf *ini.File, peerName string, peerPubKey string, peerAllowedIps string) error {
	sec, err := wgConf.NewSection("Peer")
	if err != nil {
		return err
	}
	_, err = sec.NewKey("PublicKey", peerPubKey)
	if err != nil {
		return err
	}
	_, err = sec.NewKey("AllowedIPs", peerAllowedIps)
	if err != nil {
		return err
	}
	sec.Comment = fmt.Sprintf("# %s", peerName)
	return nil
}
