package config

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
		IPFilter []string          `yaml:"ipFilter"` // IP check disabled if this is omitted or empty
		Users    map[string]string `yaml:"users"`    // maps username to password hash (bcrypt, can be generated with htpasswd)
	}
	Smtp struct {
		Enabled  bool    // required
		Host     *string // required if enabled
		User     *string // required if enabled
		Password *string // required if enabled
		From     *string // required if enabled
		Port     *int    // required if enabled
	}
	Storage struct {
		Backend string  `yaml:"backend"` // "sqlite" (default) or "postgres"
		File    *string `yaml:"file"`    // sqlite database path; required for sqlite
		Dsn     *string `yaml:"dsn"`     // postgres connection string; required for postgres
	}
	Wireguard struct {
		Ifname *string
	}
	Advertise struct {
		Endpoint          *string  // required
		AdditionalSubnets []string `yaml:"additionalSubnets"` // optional
		AdvertiseDNS      bool     `yaml:"advertiseDNS"`      // optional
	}
}

// ParseIPNetList parses a list of CIDR strings, trimming surrounding spaces
// and masking each entry. Exported for server.NewContext, which builds the
// admin IP allowlist from the parsed config.
func ParseIPNetList(input []string) ([]netip.Prefix, error) {
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

// normalizeStorage validates the mandatory storage block and fills the
// backend default. On success, cmd can open the store by branching on
// Storage.Backend alone.
func normalizeStorage(cfg *WgEnrolConfig) error {
	backend := strings.ToLower(strings.Trim(cfg.Storage.Backend, " "))
	if backend == "" {
		backend = "sqlite"
	}
	switch backend {
	case "sqlite":
		if cfg.Storage.File == nil {
			return fmt.Errorf("storage.file is required for the sqlite storage backend")
		}
	case "postgres":
		if cfg.Storage.File != nil {
			return fmt.Errorf("storage.file is only valid with the sqlite storage backend")
		}
		if cfg.Storage.Dsn == nil {
			return fmt.Errorf("storage.dsn is required for the postgres storage backend")
		}
	default:
		return fmt.Errorf("Unknown storage backend %s (supported: sqlite, postgres)", cfg.Storage.Backend)
	}
	cfg.Storage.Backend = backend
	return nil
}

func ParseConfigFile(path string) (*WgEnrolConfig, error) {
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
	if result.Wireguard.Ifname == nil {
		return nil, fmt.Errorf("wireguard.ifname parameter is required")
	}
	if result.Advertise.Endpoint == nil {
		return nil, fmt.Errorf("advertise.endpoints parameter is required")
	}
	_, parseAdvNetsErr := ParseIPNetList(result.Advertise.AdditionalSubnets)
	if parseAdvNetsErr != nil {
		return nil, parseAdvNetsErr
	}
	if _, err := ParseIPNetList(result.Admin.IPFilter); err != nil {
		return nil, err
	}
	// Check additional constraints
	if result.Server.Tls.Enabled && (result.Server.Tls.CertFile == nil || result.Server.Tls.KeyFile == nil) {
		return nil, fmt.Errorf("server.tls.certFile and server.tls.keyFile are required when TLS is enabled")
	}
	if err := normalizeStorage(&result); err != nil {
		return nil, err
	}
	return &result, nil
}
