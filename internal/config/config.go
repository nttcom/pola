package config

import (
	"log"
	"os"

	"github.com/go-yaml/yaml"
)

type Global struct {
	Address string `yaml:"address"`
	Port    string `yaml:"port"`
}

type Config struct {
	Global Global `yaml:"global"`
}

func ReadConfigFile(configFile string) (Config, error) {
	c := new(Config)

	f, err := os.Open(configFile)
	if err != nil {
		log.Fatal(err)
		return *c, err
	}
	defer f.Close()

	err = yaml.NewDecoder(f).Decode(&c)
	return *c, err
}
