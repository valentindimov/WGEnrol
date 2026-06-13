package main

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type WgEnrolConfig struct {
	Server struct {
		ListenOn *string `yaml:"listenOn"` // required
		Tls      struct {
			Enabled  bool
			CertFile *string `yaml:"certFile"` // optional
			KeyFile  *string `yaml:"keyFile"`  // optional
		}
	}
	Admin struct {
		Username     *string  // required
		PasswordHash *string  `yaml:"passwordHash"` // required
		IPFilter     []string `yaml:"ipFilter"`     // IP check disabled if this is omitted or empty
	}
	Smtp struct {
		Enabled  bool    // required
		Host     *string // required if enabled
		User     *string // required if enabled
		Password *string // required if enabled
		From     *string // required if enabled
		Port     *int    // required if enabled
	}
	Wireguard struct {
		ifname   *string // optional
		ConfFile *string `yaml:"confFile"` // required
	}
	Advertise struct {
		Endpoint  *string  // required
		PublicKey *string  `yaml:"publicKey"` // required
		Subnets   []string // required
		Dns       []string // optional
	}
}

func validateIPNetList(input []string) ([]netip.Prefix, error) {
	nets := make([]netip.Prefix, 0, len(input))
	if len(input) > 0 {
		for _, addr := range input {
			ipNet, err := netip.ParsePrefix(strings.Trim(addr, " "))
			if err != nil {
				return nil, err
			}
			nets = append(nets, ipNet.Masked())
		}
	}
	return nets, nil
}

func ParseConfigFile(path string) (*ServerContext, error) {
	// Read and unmarshal the YAML config file
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		return nil, readErr
	}
	var result WgEnrolConfig
	if err := yaml.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	// Check required fields
	if result.Server.ListenOn == nil {
		return nil, fmt.Errorf("server.listenOn parameter is required")
	}
	if result.Admin.Username == nil {
		return nil, fmt.Errorf("admin.username parameter is required")
	}
	if result.Admin.PasswordHash == nil {
		return nil, fmt.Errorf("admin.passwordHash parameter is required")
	}
	if result.Smtp.Enabled {
		if result.Smtp.Host == nil {
			return nil, fmt.Errorf("smtp.host parameter is required")
		}
		if result.Smtp.Port == nil {
			return nil, fmt.Errorf("smtp.port parameter is required")
		}
		if result.Smtp.User == nil {
			return nil, fmt.Errorf("smtp.user parameter is required")
		}
		if result.Smtp.Password == nil {
			return nil, fmt.Errorf("smtp.password parameter is required")
		}
		if result.Smtp.From == nil {
			return nil, fmt.Errorf("smtp.from parameter is required")
		}
	}
	if result.Wireguard.ConfFile == nil {
		return nil, fmt.Errorf("wireguard.confFile parameter is required")
	}
	if result.Advertise.Endpoint == nil {
		return nil, fmt.Errorf("advertise.endpoints parameter is required")
	}
	if len(result.Advertise.Subnets) == 0 {
		return nil, fmt.Errorf("advertise.subnets parameter is required and cannot be empty")
	}
	if result.Advertise.PublicKey == nil {
		return nil, fmt.Errorf("advertise.publicKey parameter is required")
	}
	_, parseAdvNetsErr := validateIPNetList(result.Advertise.Subnets)
	if parseAdvNetsErr != nil {
		return nil, parseAdvNetsErr
	}
	ipFilterNets, err := validateIPNetList(result.Admin.IPFilter)
	if err != nil {
		return nil, err
	}
	// Check additional constraints
	if result.Server.Tls.Enabled && (result.Server.Tls.CertFile == nil || result.Server.Tls.KeyFile == nil) {
		return nil, fmt.Errorf("server.tls.certFile and server.tls.keyFile are required when TLS is enabled")
	}
	// Done checking, construct server context and return
	confFile, err := loadWgConf(*result.Wireguard.ConfFile)
	if confFile == nil || err != nil {
		return nil, err
	}
	ctx := ServerContext{
		ConfFile: confFile,
		Config:   &result,

		AdminIpFilter: ipFilterNets,
	}
	return &ctx, nil
}
