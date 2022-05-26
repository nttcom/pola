package config

import (
	"os"

	"github.com/go-yaml/yaml"
)

type Pcep struct {
	Address string `yaml:"address"`
	Port    string `yaml:"port"`
}

type Grpc struct {
	Address string `yaml:"address"`
	Port    string `yaml:"port"`
}

type Global struct {
	Pcep Pcep `yaml:"pcep"`
	Grpc Grpc `yaml:"grpc"`
}

type Config struct {
	Global Global `yaml:"global"`
}

func ReadConfigFile(configFile string) (Config, error) {
	c := new(Config)

	f, err := os.Open(configFile)
	if err != nil {
		return *c, err
	}
	defer f.Close()

	err = yaml.NewDecoder(f).Decode(&c)
	return *c, err
}
