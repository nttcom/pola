// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type PCEP struct {
	Address string `yaml:"address"`
	Port    string `yaml:"port"`
}

type GRPCServer struct {
	Address string `yaml:"address"`
	Port    string `yaml:"port"`
}

type GRPCClient struct {
	Address string `yaml:"address"`
	Port    string `yaml:"port"`
}

type Log struct {
	Path  string `yaml:"path"`
	Name  string `yaml:"name"`
	Debug bool   `yaml:"debug"`
}

type GoBGP struct {
	GRPCClient GRPCClient `yaml:"grpcClient"`
}

type TED struct {
	Enable bool   `yaml:"enable"`
	Source string `yaml:"source"`
}

type Global struct {
	PCEP       PCEP       `yaml:"pcep"`
	GRPCServer GRPCServer `yaml:"grpcServer"`
	Log        Log        `yaml:"log"`
	TED        *TED       `yaml:"ted"`
	GoBGP      GoBGP      `yaml:"gobgp"`
	USidMode   bool       `yaml:"usidMode"`
}

type Config struct {
	Global Global `yaml:"global"`
}

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

	if err := yaml.NewDecoder(f).Decode(c); err != nil {
		return *c, err
	}
	return *c, nil
}
