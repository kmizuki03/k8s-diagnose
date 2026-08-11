package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kmizuki03/k8s-diagnose/internal/app"
	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"golang.org/x/term"
)

func main() {
	program := "k8s-diagnose"
	if len(os.Args) > 0 {
		program = os.Args[0]
	}
	args := os.Args[1:]
	cfg, err := config.Parse(args, program)
	if errors.Is(err, config.ErrHelp) {
		// os.File.Fd is uintptr for API compatibility, but a terminal descriptor
		// is the platform's non-negative int file descriptor.
		fd := int(os.Stdout.Fd()) // #nosec G115 -- canonical x/term descriptor conversion.
		color := os.Getenv("NO_COLOR") == "" && term.IsTerminal(fd)
		fmt.Print(config.HelpStyledFor(program, config.HelpTopic(args), color))
		return
	}
	if err != nil {
		config.PrintError(os.Stderr, program, err)
		os.Exit(1)
	}
	if cfg.Version {
		fmt.Printf("k8s-diagnose %s (Go)\n", config.Version)
		return
	}
	streams := app.Streams{In: os.Stdin, Out: os.Stdout, Err: os.Stderr}
	if config.CommandName(args) == "config" {
		if !app.InteractiveTerminal(streams) {
			config.PrintError(os.Stderr, program, errors.New("configコマンドには対話端末が必要です"))
			os.Exit(1)
		}
		_, saved, _, editErr := app.EditSettings(cfg, streams)
		if editErr != nil {
			if errors.Is(editErr, app.ErrInteractiveInterrupted) {
				os.Exit(130)
			}
			config.PrintError(os.Stderr, program, editErr)
			os.Exit(1)
		}
		if saved != "" {
			fmt.Println("設定を保存しました:", saved)
		}
		return
	}
	if len(args) == 0 && app.InteractiveTerminal(streams) {
		var quit bool
		cfg, quit, err = app.Guide(cfg, streams)
		if err != nil {
			if errors.Is(err, app.ErrInteractiveInterrupted) {
				os.Exit(130)
			}
			config.PrintError(os.Stderr, program, err)
			os.Exit(1)
		}
		if quit {
			return
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	code := app.Run(ctx, cfg, streams)
	code = interruptedExitCode(code, ctx.Err() != nil, cfg.Watch)
	os.Exit(code)
}

func interruptedExitCode(code int, interrupted bool, watch int) int {
	if !interrupted {
		return code
	}
	if watch > 0 {
		return 0
	}
	return 130
}
