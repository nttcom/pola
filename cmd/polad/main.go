// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"flag"
	"log"
	"os"

	"go.uber.org/zap"

	"github.com/nttcom/pola/internal/config"
	"github.com/nttcom/pola/pkg/logger"
	"github.com/nttcom/pola/pkg/server"
)

type Flags struct {
	ConfigFile string
}

func main() {
	f := new(Flags)
	flag.StringVar(&f.ConfigFile, "f", "polad.yaml", "Specify a configuration file")
	flag.Parse()

	c, err := config.ReadConfigFile(f.ConfigFile)
	if err != nil {
		log.Panic(err)
	}
	if err := os.MkdirAll(c.Global.Log.Path, 0755); err != nil {
		log.Panic(err)
	}
	fp, err := os.OpenFile(c.Global.Log.Path+c.Global.Log.Name, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Panic(err)
	}
	defer fp.Close()

	logger := logger.LogInit(fp)
	defer func() {
		err := logger.Sync()
		logger.Panic("Failed to logger Sync", zap.Error(err))
	}()
	zap.ReplaceGlobals(logger)

	o := new(server.PceOptions)
	o.PcepAddr = c.Global.Pcep.Address
	o.PcepPort = c.Global.Pcep.Port
	o.GrpcAddr = c.Global.Grpc.Address
	o.GrpcPort = c.Global.Grpc.Port
	if err := server.NewPce(o, logger); err != nil {
		logger.Panic("Failed to create New Server", zap.Error(err))
	}
}
