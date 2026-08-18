// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// PCEP holds the configuration for PCEP protocol settings.
type PCEP struct {
	Address string `yaml:"address"`
	Port    string `yaml:"port"`
}

// GRPCServer holds the configuration for the gRPC server.
type GRPCServer struct {
	Address string `yaml:"address"`
	Port    string `yaml:"port"`
}

// GRPCClient holds the configuration for the gRPC client.
type GRPCClient struct {
	Address string `yaml:"address"`
	Port    string `yaml:"port"`
}

// Log holds the configuration for logging.
type Log struct {
	Path  string `yaml:"path"`
	Name  string `yaml:"name"`
	Debug bool   `yaml:"debug"`
}

// GoBGP holds the configuration for GoBGP.
type GoBGP struct {
	GRPCClient GRPCClient `yaml:"grpcClient"`
}

// TED holds the configuration for TED (Traffic Engineering Database).
type TED struct {
	Enable bool   `yaml:"enable"`
	ASN    uint32 `yaml:"asn"`
	Source string `yaml:"source"`
}

// Global holds the global configuration section.
type Global struct {
	PCEP       PCEP       `yaml:"pcep"`
	GRPCServer GRPCServer `yaml:"grpcServer"`
	Log        Log        `yaml:"log"`
	TED        *TED       `yaml:"ted"`
	GoBGP      GoBGP      `yaml:"gobgp"`
	USidMode   bool       `yaml:"usidMode"`
}

// Config holds the entire configuration.
type Config struct {
	Global Global `yaml:"global"`
}

// ReadConfigFile reads and parses the config file.
func ReadConfigFile(configFile string) (Config, error) {
	c := &Config{}

	f, err := os.Open(configFile)
	if err != nil {
		return *c, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to close file \"%s\": %v\n", configFile, err)
		}
	}()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		return *c, fmt.Errorf("failed to parse config file %q: %w", configFile, err)
	}
	return *c, nil
}

// Validate checks required configuration fields.
func (c *Config) Validate() error {
	var errs []error

	if c.Global.PCEP.Address == "" {
		errs = append(errs, errors.New("global.pcep.address is required"))
	}
	if c.Global.PCEP.Port == "" {
		errs = append(errs, errors.New("global.pcep.port is required"))
	}
	if c.Global.GRPCServer.Address == "" {
		errs = append(errs, errors.New("global.grpcServer.address is required"))
	}
	if c.Global.GRPCServer.Port == "" {
		errs = append(errs, errors.New("global.grpcServer.port is required"))
	}
	if c.Global.Log.Path == "" {
		errs = append(errs, errors.New("global.log.path is required"))
	}
	if c.Global.Log.Name == "" {
		errs = append(errs, errors.New("global.log.name is required"))
	}
	if c.Global.TED == nil {
		errs = append(errs, errors.New("global.ted is required"))
	} else if c.Global.TED.Enable {
		if c.Global.TED.Source == "" {
			errs = append(errs, errors.New("global.ted.source is required when global.ted.enable is true"))
		}
		if c.Global.TED.ASN == 0 {
			errs = append(errs, errors.New("global.ted.asn is required when global.ted.enable is true"))
		}
		switch c.Global.TED.Source {
		case "gobgp":
			if c.Global.GoBGP.GRPCClient.Address == "" {
				errs = append(errs, errors.New("global.gobgp.grpcClient.address is required when global.ted.source is gobgp"))
			}
			if c.Global.GoBGP.GRPCClient.Port == "" {
				errs = append(errs, errors.New("global.gobgp.grpcClient.port is required when global.ted.source is gobgp"))
			}
		case "":
			// already reported above
		default:
			errs = append(errs, fmt.Errorf("global.ted.source %q is not supported", c.Global.TED.Source))
		}
	}

	return errors.Join(errs...)
}
