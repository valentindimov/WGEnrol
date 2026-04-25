package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type WgEnrolConfig struct {
	Server struct {
		ListenOn *string // required
		Tls      struct {
			Enabled  bool
			CertFile *string // optional
			KeyFile  *string // optional
		}
	}
	Admin struct {
		Username     *string  // required
		PasswordHash *string  // required
		IPFilter     []string // IP check disabled if this is omitted or empty
	}
	Wireguard struct {
		ifname   *string  // optional
		ConfFile *string  // required
		Subnets  []string // required
	}
	Advertise struct {
		Endpoint  *string  // required
		PublicKey *string  // required
		Subnets   []string // required
		Dns       *string  //optional
	}
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
	// Done
	return &result, nil
}
