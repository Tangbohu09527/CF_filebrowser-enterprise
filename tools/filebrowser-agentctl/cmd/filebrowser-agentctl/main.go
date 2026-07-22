package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/gtsteffaniak/filebrowser/tools/filebrowser-agentctl/internal/filebridge"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(filebridge.RunCLI(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
