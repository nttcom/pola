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

	"go.uber.org/zap"

	"github.com/nttcom/pola/internal/config"
	"github.com/nttcom/pola/internal/pkg/gobgp"
	"github.com/nttcom/pola/internal/pkg/table"
	"github.com/nttcom/pola/internal/pkg/version"
	"github.com/nttcom/pola/pkg/logger"
	"github.com/nttcom/pola/pkg/server"
)

const TEDUpdateInterval = 1 // (min)

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
		log.Panicf("failed to read config file: %v", err)
	}

	// Create log directory if it does not exist
	if err := os.MkdirAll(c.Global.Log.Path, 0755); err != nil {
		log.Panicf("failed to create log directory: %v", err)
	}

	// Open log file
	fp, err := os.OpenFile(c.Global.Log.Path+c.Global.Log.Name, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Panicf("failed to open log file: %v", err)
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
	var tedElemsChan chan []table.TEDElem
	if c.Global.TED.Enable {
		switch c.Global.TED.Source {
		case "gobgp":
			tedElemsChan = startGoBGPUpdate(&c, logger)
			if tedElemsChan == nil {
				logger.Panic("GoBGP update channel is nil")
				log.Panic("GoBGP update channel is nil")
			}
		default:
			logger.Panic("Specified TED source is not defined")
			log.Panic("specified TED source is not defined")
		}
	}

	// Start PCE server
	o := &server.PCEOptions{
		PCEPAddr:  c.Global.PCEP.Address,
		PCEPPort:  c.Global.PCEP.Port,
		GRPCAddr:  c.Global.GRPCServer.Address,
		GRPCPort:  c.Global.GRPCServer.Port,
		TEDEnable: c.Global.TED.Enable,
		USidMode:  c.Global.USidMode,
	}
	if serverErr := server.NewPCE(o, logger, tedElemsChan); serverErr.Error != nil {
		logger.Panic("Failed to start new server", zap.String("server", serverErr.Server), zap.Error(serverErr.Error))
		log.Panicf("failed to start new server: %v", serverErr.Error)
	}
}

func startGoBGPUpdate(c *config.Config, logger *zap.Logger) chan []table.TEDElem {
	if c.Global.TED == nil {
		logger.Error("TED does not exist")
		return nil
	}
	tedElemsChan := make(chan []table.TEDElem)

	go gobgp.MonitorBGPLsEvents(
		c.Global.GoBGP.GRPCClient.Address,
		c.Global.GoBGP.GRPCClient.Port,
		tedElemsChan,
		logger,
	)

	return tedElemsChan
}
