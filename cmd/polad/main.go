// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/nttcom/pola/internal/config"
	"github.com/nttcom/pola/internal/gobgp"
	"github.com/nttcom/pola/internal/version"
	"github.com/nttcom/pola/pkg/logger"
	"github.com/nttcom/pola/pkg/server"
	"github.com/nttcom/pola/pkg/table"
)

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
	if err := c.Validate(); err != nil {
		log.Panicf("invalid config file: %v", err)
	}

	// Create log directory if it does not exist. Logs can carry topology and
	// peer details, so they stay readable only by the daemon's own user.
	if err := os.MkdirAll(c.Global.Log.Path, 0750); err != nil {
		log.Panicf("failed to create log directory: %v", err)
	}

	// Open log file
	fp, err := os.OpenFile(c.Global.Log.Path+c.Global.Log.Name, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
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
		}
	}()

	if c.Global.TED.Enable && c.Global.TED.ASN == 0 {
		logger.Panic("TED is enabled but Global.TED.ASN is missing or invalid")
	}

	// Handle SIGINT/SIGTERM for graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Prepare TED update tools
	var tedElemsChan chan []table.TEDElem
	if c.Global.TED.Enable {
		switch c.Global.TED.Source {
		case "gobgp":
			tedElemsChan = startGoBGPUpdate(ctx, &c, logger)
			if tedElemsChan == nil {
				logger.Panic("GoBGP update channel is nil")
			}
		default:
			logger.Panic("Specified TED source is not defined")
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
		ASN:       c.Global.TED.ASN,
	}
	if serverErr := server.NewPCE(ctx, o, logger, tedElemsChan); serverErr.Error != nil {
		logger.Panic("Failed to start new server", zap.String("server", serverErr.Server), zap.Error(serverErr.Error))
	}
}

func startGoBGPUpdate(ctx context.Context, c *config.Config, logger *zap.Logger) chan []table.TEDElem {
	if c.Global.TED == nil {
		logger.Error("TED does not exist")
		return nil
	}
	tedElemsChan := make(chan []table.TEDElem)

	go gobgp.MonitorBGPLsEvents(
		ctx,
		c.Global.GoBGP.GRPCClient.Address,
		c.Global.GoBGP.GRPCClient.Port,
		tedElemsChan,
		logger,
	)

	return tedElemsChan
}
