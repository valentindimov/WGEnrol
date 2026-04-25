package main

import (
	"fmt"
	"net"
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
	Wireguard struct {
		ifname   *string  // optional
		ConfFile *string  `yaml:"confFile"` // required
		Subnets  []string // required
	}
	Advertise struct {
		Endpoint  *string  // required
		PublicKey *string  `yaml:"publicKey"` // required
		Subnets   []string // required
		Dns       []string // optional
	}
}

func validateIPList(input []string) error {
	if len(input) > 0 {
		for _, addr := range input {
			_, _, err := net.ParseCIDR(strings.Trim(addr, " "))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func ParseConfigFile(path string) (*WgEnrolConfig, error) {
	// Read and unmarshal the YAML config file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var result WgEnrolConfig
	err = yaml.Unmarshal(data, &result)
	if err != nil {
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
	if result.Wireguard.ConfFile == nil {
		return nil, fmt.Errorf("wireguard.confFile parameter is required")
	}
	if len(result.Wireguard.Subnets) == 0 {
		return nil, fmt.Errorf("wireguard.subnets parameter is required and cannot be empty")
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
	err = validateIPList(result.Wireguard.Subnets)
	if err != nil {
		return nil, err
	}
	err = validateIPList(result.Advertise.Subnets)
	if err != nil {
		return nil, err
	}
	err = validateIPList(result.Admin.IPFilter)
	if err != nil {
		return nil, err
	}
	// Check additional constraints
	if result.Server.Tls.Enabled && (result.Server.Tls.CertFile == nil || result.Server.Tls.KeyFile == nil) {
		return nil, fmt.Errorf("server.tls.certFile and server.tls.keyFile are required when TLS is enabled")
	}
	// Done
	return &result, nil
}
