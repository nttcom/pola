// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

// Command polad runs the pola PCE server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/nttcom/pola/internal/config"
	"github.com/nttcom/pola/internal/gobgp"
	"github.com/nttcom/pola/internal/version"
	"github.com/nttcom/pola/pkg/logger"
	"github.com/nttcom/pola/pkg/server"
	"github.com/nttcom/pola/pkg/table"
)

const (
	versionFlag    = "--version"
	tedSourceGoBGP = "gobgp"
)

type flags struct {
	configFile string
}

type monitorBGPLsEventsFunc func(ctx context.Context, serverAddr string, serverPort string, tedChan chan []table.TEDElem, lg *logger.Logger)

type newPCEFunc func(ctx context.Context, o *server.PCEOptions, lg *logger.Logger, tedElemsChan chan []table.TEDElem) server.Error

type runDeps struct {
	newPCE     newPCEFunc
	monitorBGP monitorBGPLsEventsFunc
}

func defaultRunDeps() runDeps {
	return runDeps{
		newPCE:     server.NewPCE,
		monitorBGP: gobgp.MonitorBGPLsEvents,
	}
}

func main() {
	os.Exit(mainRun(os.Args[1:]))
}

func mainRun(args []string) int {
	if err := run(args, defaultRunDeps()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	return 0
}

func run(args []string, deps runDeps) error {
	if len(args) > 0 && args[0] == versionFlag {
		fmt.Println("polad " + version.Version())
		return nil
	}

	fs := flag.NewFlagSet("polad", flag.ContinueOnError)
	f := &flags{}
	fs.StringVar(&f.configFile, "f", "polad.yaml", "Specify a configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	c, err := loadConfig(f.configFile)
	if err != nil {
		return err
	}

	fp, err := openLogFile(&c)
	if err != nil {
		return err
	}
	defer func() {
		if err := fp.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to close log file \"%s\": %v\n", c.Global.Log.Path+c.Global.Log.Name, err)
		}
	}()

	level, err := parseLogLevel(c.Global.Log.Level)
	if err != nil {
		return fmt.Errorf("invalid config file: %w", err)
	}

	lg := logger.New(fp, os.Stdout, level)
	defer func() {
		if err := lg.Sync(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to sync logger: %v\n", err)
		}
	}()

	// Cancelling ctx on SIGINT/SIGTERM triggers graceful shutdown of the PCE
	// servers and BGP-LS monitor.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	tedElemsChan, err := newTEDElemsChan(ctx, &c, lg, deps.monitorBGP)
	if err != nil {
		return err
	}

	o := &server.PCEOptions{
		PCEPAddr:         c.Global.PCEP.Address,
		PCEPPort:         c.Global.PCEP.Port,
		GRPCAddr:         c.Global.GRPCServer.Address,
		GRPCPort:         c.Global.GRPCServer.Port,
		TEDEnable:        c.Global.TED.Enable,
		USidMode:         c.Global.USidMode,
		ASN:              c.Global.TED.ASN,
		Keepalive:        c.Global.PCEP.Keepalive,
		DeadTimer:        c.Global.PCEP.DeadTimer,
		MinKeepalive:     c.Global.PCEP.MinKeepalive,
		MaxKeepalive:     c.Global.PCEP.MaxKeepalive,
		AllowNegotiation: c.Global.PCEP.AllowNegotiation,
	}
	if serverErr := deps.newPCE(ctx, o, lg, tedElemsChan); serverErr.Error != nil {
		return fmt.Errorf("server %q failed: %w", serverErr.Server, serverErr.Error)
	}

	return nil
}

// parseLogLevel converts a config-file log level into a logger.Level.
// An empty string is treated as info.
func parseLogLevel(level string) (logger.Level, error) {
	switch level {
	case "", "info":
		return logger.LevelInfo, nil
	case "debug":
		return logger.LevelDebug, nil
	case "warn":
		return logger.LevelWarn, nil
	case "error":
		return logger.LevelError, nil
	default:
		return 0, fmt.Errorf("global.log.level %q is not supported", level)
	}
}

func loadConfig(configFile string) (config.Config, error) {
	c, err := config.ReadConfigFile(configFile)
	if err != nil {
		return c, fmt.Errorf("failed to read config file: %w", err)
	}
	if err := c.Validate(); err != nil {
		return c, fmt.Errorf("invalid config file: %w", err)
	}

	return c, nil
}

func openLogFile(c *config.Config) (*os.File, error) {
	// Create the log directory if it does not exist.
	if err := os.MkdirAll(c.Global.Log.Path, 0o750); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	fp, err := os.OpenFile(c.Global.Log.Path+c.Global.Log.Name, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}
	// OpenFile's mode does not apply to existing files.
	if err := fp.Chmod(0o600); err != nil {
		_ = fp.Close()
		return nil, fmt.Errorf("failed to restrict log file permissions: %w", err)
	}

	return fp, nil
}

func newTEDElemsChan(ctx context.Context, c *config.Config, lg *logger.Logger, monitorBGP monitorBGPLsEventsFunc) (chan []table.TEDElem, error) {
	if c.Global.TED == nil || !c.Global.TED.Enable {
		return nil, nil
	}
	if c.Global.TED.ASN == 0 {
		return nil, errors.New("TED is enabled but Global.TED.ASN is missing or invalid")
	}
	if c.Global.TED.Source != tedSourceGoBGP {
		return nil, fmt.Errorf("specified TED source %q is not defined", c.Global.TED.Source)
	}

	tedElemsChan := make(chan []table.TEDElem)

	go monitorBGP(
		ctx,
		c.Global.GoBGP.GRPCClient.Address,
		c.Global.GoBGP.GRPCClient.Port,
		tedElemsChan,
		lg,
	)

	return tedElemsChan, nil
}
