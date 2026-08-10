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
	cfg, err := config.Parse(os.Args[1:], program)
	if errors.Is(err, config.ErrHelp) {
		// os.File.Fd is uintptr for API compatibility, but a terminal descriptor
		// is the platform's non-negative int file descriptor.
		fd := int(os.Stdout.Fd()) // #nosec G115 -- canonical x/term descriptor conversion.
		color := os.Getenv("NO_COLOR") == "" && term.IsTerminal(fd)
		fmt.Print(config.HelpStyled(program, color))
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
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	code := app.Run(ctx, cfg, app.Streams{In: os.Stdin, Out: os.Stdout, Err: os.Stderr})
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
