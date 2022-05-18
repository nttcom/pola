// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"flag"

    "go.uber.org/zap"

	"github.com/nttcom/pola/internal/config"
	"github.com/nttcom/pola/pkg/server"
)

type Flags struct {
	ConfigFile string
}

func main() {
    logger, _ := zap.NewProduction()
    defer logger.Sync()
    zap.ReplaceGlobals(logger)

	f := new(Flags)
	flag.StringVar(&f.ConfigFile, "f", "polad.yaml", "Specify a configuration file")
	flag.Parse()

	c, err := config.ReadConfigFile(f.ConfigFile)
	if err != nil {
        logger.Fatal("Failed to read config file", zap.Error(err))
	}

	o := new(server.PceOptions)
	o.PcepAddr = c.Global.Address
	o.PcepPort = c.Global.Port
	if err := server.NewPce(o); err != nil {
        logger.Fatal("Failed to create New Server", zap.Error(err))
	}
}
