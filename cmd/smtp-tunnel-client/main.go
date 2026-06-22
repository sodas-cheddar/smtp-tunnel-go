// Command smtp-tunnel-client is a thin wrapper that invokes the client
// subcommand of smtp-tunnel-go. It exists so the auto-generated client
// ZIP package (produced by `smtp-tunnel-go adduser <name>`) ships with a
// single-purpose binary that has the same default config-file name as
// the Python original.
//
// Usage:
//
//	smtp-tunnel-client [-c config.yaml] [-d]
//	         [--server HOST] [--server-port PORT] [-p SOCKS_PORT]
//	         [-u USERNAME] [-s SECRET] [--ca-cert FILE]
//
// This is identical to `smtp-tunnel-go client ...` — it just saves a
// subcommand prefix. The resulting binary is what gets zipped into the
// user package by adduser.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/sodas-cheddar/smtp-tunnel-go/internal/cli"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var c cli.ClientCmd
	c.ParseFlags(os.Args[1:])
	os.Exit(c.Run(ctx))
}
