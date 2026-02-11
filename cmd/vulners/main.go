package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/lmittmann/tint"
	"go.uber.org/fx"

	"github.com/kidoz/vulners-cli/internal/cache"
	icmd "github.com/kidoz/vulners-cli/internal/cmd"
	"github.com/kidoz/vulners-cli/internal/config"
	"github.com/kidoz/vulners-cli/internal/intel"
	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/kidoz/vulners-cli/internal/report"
)

// exitCode is set by run() and read by main() after app.Stop() completes.
// This ensures Fx lifecycle hooks (e.g. SQLite close) run before the process exits.
var exitCode int

func main() {
	app := fx.New(
		fx.Provide(
			config.Load,
			provideLogger,
			provideCLI,
			provideDeps,
			provideCache,
		),
		fx.Invoke(run),
		fx.NopLogger,
	)

	if err := app.Start(context.Background()); err != nil {
		slog.Error("failed to start", "error", err)
		// Still call Stop to clean up partially-initialized resources (e.g. SQLite).
		_ = app.Stop(context.Background())
		os.Exit(int(icmd.ExitRuntimeError))
	}

	if err := app.Stop(context.Background()); err != nil {
		slog.Error("failed to stop", "error", err)
	}

	os.Exit(exitCode)
}

func provideLogger(cfg *config.Config, cli *icmd.CLI) (*slog.Logger, *slog.LevelVar) {
	lvl := &slog.LevelVar{}

	// Set initial level from env-based config.
	switch {
	case cfg.Quiet || cli.Agent:
		lvl.Set(slog.LevelError)
	case cfg.Verbose:
		lvl.Set(slog.LevelDebug)
	default:
		lvl.Set(slog.LevelInfo)
	}

	useColor := isTerminal() && !cli.NoColor && !cli.Agent

	var handler slog.Handler
	if useColor {
		handler = tint.NewHandler(os.Stderr, &tint.Options{
			Level:      lvl,
			TimeFormat: time.Kitchen,
		})
	} else {
		handler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: lvl,
		})
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)
	return logger, lvl
}

func isTerminal() bool {
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func provideCLI() *icmd.CLI {
	return &icmd.CLI{}
}

func provideDeps(cfg *config.Config, logger *slog.Logger) (*icmd.Deps, error) {
	var intelClient intel.Client
	if cfg.APIKey != "" {
		var err error
		intelClient, err = intel.NewVulnersClient(cfg.APIKey, logger)
		if err != nil {
			return nil, fmt.Errorf("creating Vulners client: %w (check VULNERS_API_KEY)", err)
		}
	}
	return &icmd.Deps{Intel: intelClient}, nil
}

func provideCache(lc fx.Lifecycle, cfg *config.Config, logger *slog.Logger) cache.Store {
	store, err := cache.NewSQLiteStore(cfg.DBPath, logger)
	if err != nil {
		logger.Warn("failed to open cache database; offline features degraded", "error", err)
		return cache.NewNopStore()
	}
	lc.Append(fx.Hook{
		OnStop: func(_ context.Context) error {
			return store.Close()
		},
	})
	return store
}

// kongExitSignal is used to unwind from Kong's exit calls (--help, parse errors)
// back to run() via panic/recover, ensuring Fx lifecycle hooks still run.
type kongExitSignal struct{ code int }

func run(cfg *config.Config, cli *icmd.CLI, deps *icmd.Deps, store cache.Store, logger *slog.Logger, lvl *slog.LevelVar) {
	// Recover from Kong's exit calls so app.Stop() still runs.
	// Non-Kong panics are logged and result in exit code 3 (runtime error).
	defer func() {
		if r := recover(); r != nil {
			if sig, ok := r.(kongExitSignal); ok {
				exitCode = sig.code
				return
			}
			slog.Error("unexpected panic", "panic", r)
			exitCode = int(icmd.ExitRuntimeError)
		}
	}()

	// Propagate build version to packages that include tool metadata.
	report.Version = icmd.Version
	intel.Version = icmd.Version

	// Create signal-aware context for graceful cancellation on SIGINT/SIGTERM.
	signalCtx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	kongCtx := kong.Parse(cli,
		kong.Name("vulners"),
		kong.Description("CLI vulnerability scanner powered by Vulners"),
		kong.UsageOnError(),
		kong.Writers(os.Stderr, os.Stderr),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
		kong.Exit(func(code int) {
			panic(kongExitSignal{code: code})
		}),
		kong.Bind(deps),
		kong.BindTo(store, (*cache.Store)(nil)),
		kong.BindTo(signalCtx, (*context.Context)(nil)),
		kong.Bind(logger),
	)

	// Apply config values for boolean flags that Kong defaults to false.
	// Kong parsing overwrites any values pre-seeded into the CLI struct,
	// so we re-apply config after parsing — but only when the CLI flag was
	// NOT explicitly passed. This ensures --verbose beats quiet: true in YAML.
	applyConfigFlags(cfg, cli, lvl)

	if err := kongCtx.Run(cli, deps, store, logger, kongCtx.Kong); err != nil {
		var exitErr *model.ExitError
		if errors.As(err, &exitErr) {
			exitCode = int(exitErr.Code)
			return
		}
		logger.Error("command failed", "error", err)
		exitCode = int(icmd.ExitRuntimeError)
	}
}

// scanExplicitFlags scans os.Args for boolean flags that were explicitly passed
// on the command line, including --flag=value and combined short forms like -vq.
func scanExplicitFlags() map[string]bool {
	explicit := make(map[string]bool)
	for _, f := range os.Args[1:] {
		// Long flags: --verbose, --verbose=true, --quiet, --quiet=false, --offline
		switch {
		case strings.HasPrefix(f, "--verbose"):
			explicit["verbose"] = true
		case strings.HasPrefix(f, "--quiet"):
			explicit["quiet"] = true
		case strings.HasPrefix(f, "--offline"):
			explicit["offline"] = true
		}
		// Short flags: -v, -q, or combined -vq
		if len(f) >= 2 && f[0] == '-' && f[1] != '-' {
			for _, ch := range f[1:] {
				switch ch {
				case 'v':
					explicit["verbose"] = true
				case 'q':
					explicit["quiet"] = true
				}
			}
		}
	}
	return explicit
}

// applyConfigFlags merges config-file boolean flags into the CLI struct when
// the user did not explicitly pass them on the command line, then updates the
// log level to match the final effective flags.
func applyConfigFlags(cfg *config.Config, cli *icmd.CLI, lvl *slog.LevelVar) {
	// --agent implies --output json, --quiet, --no-color.
	if cli.Agent {
		cli.Output = "json"
		cli.Quiet = true
		cli.NoColor = true
	}

	ef := scanExplicitFlags()
	if cfg.Offline && !ef["offline"] {
		cli.Offline = true
	}
	if cfg.Quiet && !ef["quiet"] && !ef["verbose"] {
		cli.Quiet = true
	}
	if cfg.Verbose && !ef["verbose"] && !ef["quiet"] {
		cli.Verbose = true
	}

	// Update log level based on final effective flags.
	switch {
	case cli.Quiet:
		lvl.Set(slog.LevelError)
	case cli.Verbose:
		lvl.Set(slog.LevelDebug)
	}
}
