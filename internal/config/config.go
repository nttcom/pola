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

type Pcep struct {
	Address string `yaml:"address"`
	Port    string `yaml:"port"`
}

type GrpcServer struct {
	Address string `yaml:"address"`
	Port    string `yaml:"port"`
}

type GrpcClient struct {
	Address string `yaml:"address"`
	Port    string `yaml:"port"`
}

type Log struct {
	Path  string `yaml:"path"`
	Name  string `yaml:"name"`
	Debug bool   `yaml:"debug"`
}

type Gobgp struct {
	GrpcClient GrpcClient `yaml:"grpc-client"`
}

type Ted struct {
	Enable bool   `yaml:"enable"`
	Source string `yaml:"source"`
}

type Global struct {
	Pcep       Pcep       `yaml:"pcep"`
	GrpcServer GrpcServer `yaml:"grpc-server"`
	Log        Log        `yaml:"log"`
	Ted        *Ted       `yaml:"ted"`
	Gobgp      Gobgp      `yaml:"gobgp"`
	USidMode   bool       `yaml:"usid-mode"`
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
