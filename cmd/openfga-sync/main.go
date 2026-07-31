// Package main is the openfga-sync daemon.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/FuturFusion/openfga-sync/internal/source"
	"github.com/FuturFusion/openfga-sync/internal/syncer"
	"github.com/FuturFusion/openfga-sync/internal/version"
	"github.com/FuturFusion/openfga-sync/shared/config"
)

type cmdDaemon struct {
	flagConfig  string
	flagDebug   bool
	flagDryRun  bool
	flagOneShot bool
}

func main() {
	daemonCmd := cmdDaemon{}

	app := &cobra.Command{}
	app.Use = "openfga-sync"
	app.Short = "Synchronize identity providers with Incus OpenFGA stores"
	app.Long = `Description:
  Synchronize identity providers with Incus OpenFGA stores

  This daemon pulls group and role information from a number of data
  sources (AD/LDAP, Rauthy) and converts it into OpenFGA relationship
  tuples on the OpenFGA stores used by Incus clusters.
`
	app.RunE = daemonCmd.run
	app.SilenceUsage = true
	app.SilenceErrors = true
	app.CompletionOptions = cobra.CompletionOptions{DisableDefaultCmd: true}

	app.PersistentFlags().StringVar(&daemonCmd.flagConfig, "config", "/etc/openfga-sync/config.yml", "Path to the configuration file")
	app.PersistentFlags().BoolVar(&daemonCmd.flagDebug, "debug", false, "Enable debug logging")
	app.PersistentFlags().BoolVar(&daemonCmd.flagDryRun, "dry-run", false, "Only report the changes that would be made")
	app.PersistentFlags().BoolVar(&daemonCmd.flagOneShot, "one-shot", false, "Run a single synchronization pass and exit")

	app.SetVersionTemplate("{{.Version}}\n")
	app.Version = version.Version

	err := app.Execute()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)

		os.Exit(1)
	}
}

func (c *cmdDaemon) run(_ *cobra.Command, _ []string) error {
	// Set up logging.
	level := slog.LevelInfo
	if c.flagDebug {
		level = slog.LevelDebug
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	// Load the initial configuration.
	engine, interval, err := c.load()
	if err != nil {
		return err
	}

	// Handle the signals.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)

	// Run the synchronization loop.
	for {
		err := engine.Sync(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			slog.Error("Synchronization failed", slog.Any("error", err))
		}

		if c.flagOneShot {
			return err
		}

		select {
		case <-ctx.Done():
			return nil

		case <-reload:
			slog.Info("Reloading configuration")

			newEngine, newInterval, err := c.load()
			if err != nil {
				slog.Error("Failed to reload configuration", slog.Any("error", err))

				continue
			}

			engine = newEngine
			interval = newInterval

		case <-time.After(interval):
		}
	}
}

// load parses the configuration and assembles the synchronization engine.
func (c *cmdDaemon) load() (*syncer.Engine, time.Duration, error) {
	cfg, err := config.Load(c.flagConfig)
	if err != nil {
		return nil, 0, err
	}

	engine := &syncer.Engine{
		DryRun:             c.flagDryRun,
		Authoritative:      cfg.OpenFGA.Authoritative,
		SkipMissingObjects: cfg.OpenFGA.SkipMissingObjects,
	}

	// The state is only used when not running in authoritative mode.
	if !cfg.OpenFGA.Authoritative {
		state, err := syncer.LoadState(cfg.Daemon.StateDir)
		if err != nil {
			return nil, 0, err
		}

		engine.State = state
	}

	for i := range cfg.Sources {
		src := &cfg.Sources[i]

		switch src.Type {
		case "ldap":
			ldap := source.NewLDAP(src.Name, src.LDAP)

			if src.LDAP.SyncRoles {
				engine.Sources = append(engine.Sources, ldap)
			}

			if src.LDAP.SyncGroups {
				engine.Resolvers = append(engine.Resolvers, ldap)
			}

		case "rauthy":
			rauthy, err := source.NewRauthy(src.Name, src.Rauthy)
			if err != nil {
				return nil, 0, err
			}

			if src.Rauthy.SyncRoles {
				engine.Sources = append(engine.Sources, rauthy)
			}

			if src.Rauthy.SyncGroups {
				engine.Resolvers = append(engine.Resolvers, rauthy)
			}

		default:
			return nil, 0, fmt.Errorf("unsupported source type %q", src.Type)
		}
	}

	engine.Instance = syncer.NewInstance(&cfg.OpenFGA)

	return engine, time.Duration(cfg.Daemon.Interval), nil
}
