// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"flag"
	"log"
	"os"
	"time"

	"go.uber.org/zap"

	"github.com/nttcom/pola/internal/config"
	"github.com/nttcom/pola/internal/pkg/gobgp"
	"github.com/nttcom/pola/internal/pkg/table"
	"github.com/nttcom/pola/pkg/logger"
	"github.com/nttcom/pola/pkg/server"
)

const (
	TED_UPDATE_INTERVAL = 10 // (min)
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

	tedElemsChan := make(chan []table.TedElem)

	// Prepare ted update tools
	if c.Global.Ted.Enable {
		if c.Global.Ted.Source == "gobgp" {
			go func() {
				for {
					tedElems, err := gobgp.GetBgplsNlris(c.Global.Gobgp.GrpcClient.Address, c.Global.Gobgp.GrpcClient.Port)

					if err != nil {
						logger.Panic("Failed session with GoBGP", zap.Error(err))
					}
					tedElemsChan <- tedElems
					time.Sleep(TED_UPDATE_INTERVAL * time.Minute)
				}

			}()
		} else {
			// TODO: Prepare other TED update methods
			logger.Panic("Specified tool is not defined", zap.Error(err))
		}
	}

	o := new(server.PceOptions)
	o.PcepAddr = c.Global.Pcep.Address
	o.PcepPort = c.Global.Pcep.Port
	o.GrpcAddr = c.Global.GrpcServer.Address
	o.GrpcPort = c.Global.GrpcServer.Port
	o.TedEnable = c.Global.Ted.Enable
	if err := server.NewPce(o, logger, tedElemsChan); err != nil {
		logger.Panic("Failed to create New Server", zap.Error(err))
	}
}
