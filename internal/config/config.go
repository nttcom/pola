// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

// Package config loads and validates polad's configuration.
package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/nttcom/pola/pkg/packet/pcep"
)

// PCEP holds the configuration for PCEP protocol settings.
type PCEP struct {
	Address          string `yaml:"address"`
	Port             string `yaml:"port"`
	Keepalive        *uint8 `yaml:"keepalive"`
	DeadTimer        *uint8 `yaml:"deadTimer"`
	MinKeepalive     *uint8 `yaml:"minKeepalive"`
	MaxKeepalive     *uint8 `yaml:"maxKeepalive"`
	AllowNegotiation *bool  `yaml:"allowNegotiation"`
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
	Level string `yaml:"level"`
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

	//nolint:gosec // G304: configFile is chosen by the operator.
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

// RFC 5440 §7.3 default Keepalive.
const defaultKeepalive uint8 = 30

func (p PCEP) validate() []error {
	var errs []error

	if p.Address == "" {
		errs = append(errs, errors.New("global.pcep.address is required"))
	}
	if p.Port == "" {
		errs = append(errs, errors.New("global.pcep.port is required"))
	}
	keepalive := defaultKeepalive
	if p.Keepalive != nil {
		keepalive = *p.Keepalive
	}
	if err := pcep.ValidateTimers(keepalive, p.DeadTimer); err != nil {
		errs = append(errs, fmt.Errorf("global.pcep.%w", err))
	}
	if p.MinKeepalive != nil && p.MaxKeepalive != nil && *p.MinKeepalive > *p.MaxKeepalive {
		errs = append(errs, errors.New("global.pcep.minKeepalive must be <= global.pcep.maxKeepalive"))
	}

	return errs
}

// validateTED checks the TED configuration and, when TED sources a backend
// such as gobgp, the corresponding backend client settings.
func (g Global) validateTED() []error {
	if g.TED == nil {
		return []error{errors.New("global.ted is required")}
	}
	if !g.TED.Enable {
		return nil
	}

	var errs []error
	if g.TED.Source == "" {
		errs = append(errs, errors.New("global.ted.source is required when global.ted.enable is true"))
	}
	if g.TED.ASN == 0 {
		errs = append(errs, errors.New("global.ted.asn is required when global.ted.enable is true"))
	}
	switch g.TED.Source {
	case "gobgp":
		if g.GoBGP.GRPCClient.Address == "" {
			errs = append(errs, errors.New("global.gobgp.grpcClient.address is required when global.ted.source is gobgp"))
		}
		if g.GoBGP.GRPCClient.Port == "" {
			errs = append(errs, errors.New("global.gobgp.grpcClient.port is required when global.ted.source is gobgp"))
		}
	case "":
		// already reported above
	default:
		errs = append(errs, fmt.Errorf("global.ted.source %q is not supported", g.TED.Source))
	}

	return errs
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	errs := c.Global.PCEP.validate()

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
	errs = append(errs, c.Global.validateTED()...)

	return errors.Join(errs...)
}
