// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"go.uber.org/zap"

	"github.com/nttcom/pola/internal/config"
	"github.com/nttcom/pola/internal/pkg/gobgp"
	"github.com/nttcom/pola/internal/pkg/table"
	"github.com/nttcom/pola/internal/pkg/version"
	"github.com/nttcom/pola/pkg/logger"
	"github.com/nttcom/pola/pkg/server"
)

const TED_UPDATE_INTERVAL = 10 // (min)

type flags struct {
	configFile string
}

func main() {
	// Check if --version flag was passed
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println("polad " + version.Version())
		return
	}

	// Parse flags
	f := &flags{}
	flag.StringVar(&f.configFile, "f", "polad.yaml", "Specify a configuration file")
	flag.Parse()

	// Read configuration file
	c, err := config.ReadConfigFile(f.configFile)
	if err != nil {
		log.Panic(err)
	}

	// Create log directory if it does not exist
	if err := os.MkdirAll(c.Global.Log.Path, 0755); err != nil {
		log.Panic(err)
	}

	// Open log file
	fp, err := os.OpenFile(c.Global.Log.Path+c.Global.Log.Name, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Panic(err)
	}
	defer func() {
		if err := fp.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to close log file \"%s\": %v\n", c.Global.Log.Path+c.Global.Log.Name, err)
		}
	}()

	// Initialize logger
	logger := logger.LogInit(fp, c.Global.Log.Debug)
	defer func() {
		if err := logger.Sync(); err != nil {
			logger.Panic("Failed to sync logger", zap.Error(err))
			log.Panicf("failed to sync logger: %v", err)
		}
	}()

	// Prepare TED update tools
	var tedElemsChan chan []table.TedElem
	if c.Global.Ted.Enable {
		switch c.Global.Ted.Source {
		case "gobgp":
			tedElemsChan = startGobgpUpdate(&c, logger)
			if tedElemsChan == nil {
				logger.Panic("GoBGP update channel is nil")
				log.Panic("GoBGP update channel is nil")
			}
		default:
			logger.Panic("Specified TED source is not defined")
			log.Panic()
		}
	}

	// Start PCE server
	o := &server.PceOptions{
		PcepAddr:  c.Global.Pcep.Address,
		PcepPort:  c.Global.Pcep.Port,
		GrpcAddr:  c.Global.GrpcServer.Address,
		GrpcPort:  c.Global.GrpcServer.Port,
		TedEnable: c.Global.Ted.Enable,
		USidMode:  c.Global.USidMode,
	}
	if serverErr := server.NewPce(o, logger, tedElemsChan); serverErr.Error != nil {
		logger.Panic("Failed to start new server", zap.String("server", serverErr.Server), zap.Error(serverErr.Error))
		log.Panic()
	}
}

func startGobgpUpdate(c *config.Config, logger *zap.Logger) chan []table.TedElem {
	if c.Global.Ted == nil {
		logger.Error("TED does not exist")
		return nil
	}
	tedElemsChan := make(chan []table.TedElem)

	go func() {
		for {
			tedElems, err := gobgp.GetBgplsNlris(c.Global.Gobgp.GrpcClient.Address, c.Global.Gobgp.GrpcClient.Port)
			logger.Debug("Request TED update", zap.String("source", "GoBGP"), zap.String("session", c.Global.Gobgp.GrpcClient.Address+":"+c.Global.Gobgp.GrpcClient.Port))
			if err != nil {
				logger.Error("Failed session with GoBGP", zap.Error(err))
			} else {
				tedElemsChan <- tedElems
			}
			time.Sleep(TED_UPDATE_INTERVAL * time.Minute)
		}
	}()

	return tedElemsChan
}
