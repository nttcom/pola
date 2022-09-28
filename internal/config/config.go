package config

import (
	"os"

	"github.com/go-yaml/yaml"
)

type Pcep struct {
	Address string `yaml:"address"`
	Port    string `yaml:"port"`
}

type GrpcServer struct {
	Address string `yaml:"address"`
	Port    string `yaml:"port"`
}

type Log struct {
	Path string `yaml:"path"`
	Name string `yaml:"name"`
}

type GrpcClient struct {
	Address string `yaml:"address"`
	Port    string `yaml:"port"`
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
	Ted        Ted        `yaml:"ted"`
	Gobgp      Gobgp      `yaml:"gobgp"`
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
