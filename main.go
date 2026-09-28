// Command godig is a DNS resolver and lookup tool written from scratch.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/useless-husband/godig/internal/cli"
)

// version is set at build time: -ldflags "-X main.version=v0.1.0".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(cli.Run(ctx, os.Args[1:], &cli.Env{Stdout: os.Stdout, Stderr: os.Stderr, Version: version}))
}
