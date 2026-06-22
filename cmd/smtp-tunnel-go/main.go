// Command smtp-tunnel-go is the server-side all-in-one binary. It
// exposes subcommands for running the server, running the client,
// generating certs, and managing users.
//
// Usage:
//
//	smtp-tunnel-go server    [-c config.yaml] [-d]
//	smtp-tunnel-go client    [-c config.yaml] [-d]
//	smtp-tunnel-go gencerts  --hostname mail.example.com --output-dir /etc/smtp-tunnel
//	smtp-tunnel-go adduser   <username> [-w 1.2.3.4] [-w 10.0.0.0/8] [--no-logging]
//	smtp-tunnel-go deluser   <username> [-f]
//	smtp-tunnel-go listusers [-v]
//	smtp-tunnel-go version
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sodas-cheddar/smtp-tunnel-go/internal/cli"
)

const version = "2.0.0-go"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	// Catch SIGINT/SIGTERM early so subcommands inherit a cancellable
	// context. Some subcommands (gencerts, listusers, etc.) don't need
	// it but accepting it is harmless.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "server":
		var c cli.ServerCmd
		c.ParseFlags(args)
		os.Exit(c.Run(ctx))

	case "client":
		var c cli.ClientCmd
		c.ParseFlags(args)
		os.Exit(c.Run(ctx))

	case "gencerts":
		var c cli.GenCertsCmd
		c.ParseFlags(args)
		os.Exit(c.Run(ctx))

	case "adduser":
		var c cli.AddUserCmd
		if err := c.ParseFlags(args); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		os.Exit(c.Run(ctx))

	case "deluser":
		var c cli.DelUserCmd
		if err := c.ParseFlags(args); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		os.Exit(c.Run(ctx))

	case "listusers":
		var c cli.ListUsersCmd
		if err := c.ParseFlags(args); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		os.Exit(c.Run(ctx))

	case "version", "--version", "-v":
		fmt.Println("smtp-tunnel-go", version)

	case "help", "--help", "-h":
		printUsage()

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Print(`smtp-tunnel-go - high-speed SMTP-disguised tunnel proxy

Usage:
  smtp-tunnel-go <command> [flags]

Commands:
  server       Run the tunnel server (on the VPS)
  client       Run the tunnel client + local SOCKS5 proxy (on the user's machine)
  gencerts     Generate CA + server TLS certificates
  adduser      Add a user and generate a client ZIP package
  deluser      Remove a user
  listusers    List all configured users
  version      Print version info
  help         Show this message

Run ` + "`smtp-tunnel-go <command> --help`" + ` for command-specific flags.

Examples:
  # Server
  smtp-tunnel-go gencerts --hostname mail.example.com --output-dir /etc/smtp-tunnel
  smtp-tunnel-go adduser alice
  smtp-tunnel-go server -c /etc/smtp-tunnel/config.yaml

  # Client
  smtp-tunnel-go client -c config.yaml

  # Or just use the auto-generated client ZIP from ` + "`adduser`" + `.
`)
}
