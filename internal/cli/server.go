// Package cli wires the tunnel/socks5/certs/config packages into the
// smtp-tunnel-go binary's subcommands.
package cli

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/sodas-cheddar/smtp-tunnel-go/internal/config"
	"github.com/sodas-cheddar/smtp-tunnel-go/internal/socks5"
	"github.com/sodas-cheddar/smtp-tunnel-go/internal/tunnel"
)

// ServerCmd is the `smtp-tunnel-go server` subcommand. It loads
// config.yaml + users.yaml and serves tunnel connections on the
// configured port.
type ServerCmd struct {
	ConfigPath string
	UsersPath  string
	Debug      bool
}

// ParseFlags parses the server subcommand's flags.
func (c *ServerCmd) ParseFlags(args []string) {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.StringVar(&c.ConfigPath, "config", "config.yaml", "config file")
	fs.StringVar(&c.ConfigPath, "c", "config.yaml", "config file (shorthand)")
	fs.StringVar(&c.UsersPath, "users", "", "users file (default: from config)")
	fs.StringVar(&c.UsersPath, "u", "", "users file (shorthand)")
	fs.BoolVar(&c.Debug, "debug", false, "enable debug logging")
	fs.BoolVar(&c.Debug, "d", false, "enable debug logging (shorthand)")
	_ = fs.Parse(args)
}

// Run executes the server. Returns a process exit code.
func (c *ServerCmd) Run(ctx context.Context) int {
	logLevel := slog.LevelInfo
	if c.Debug {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	cfg, err := config.Load(c.ConfigPath)
	if err != nil {
		logger.Error("load config failed", "path", c.ConfigPath, "err", err)
		return 1
	}

	usersPath := c.UsersPath
	if usersPath == "" {
		usersPath = cfg.Server.UsersFile
	}
	users, err := config.LoadUsers(usersPath)
	if err != nil {
		logger.Error("load users failed", "path", usersPath, "err", err)
		return 1
	}
	if len(users) == 0 {
		logger.Error("no users configured",
			"path", usersPath,
			"hint", "run `smtp-tunnel-go adduser <name>` to create one")
		return 1
	}

	// Load the TLS cert.
	cert, err := tls.LoadX509KeyPair(cfg.Server.CertFile, cfg.Server.KeyFile)
	if err != nil {
		logger.Error("load cert failed",
			"cert", cfg.Server.CertFile,
			"key", cfg.Server.KeyFile,
			"err", err)
		return 1
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   cfg.Server.Hostname,
		MinVersion:   tls.VersionTLS12,
	}

	// Resolve the listen address.
	addr := net.JoinHostPort(cfg.Server.Host, fmt.Sprintf("%d", cfg.Server.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("listen failed", "addr", addr, "err", err)
		return 1
	}

	logger.Info("smtp tunnel server listening",
		"addr", addr,
		"hostname", cfg.Server.Hostname,
		"users", len(users))

	// Handle SIGINT / SIGTERM.
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			if errors.Is(err, net.ErrClosed) {
				break
			}
			logger.Info("accept failed", "err", err)
			continue
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(true)
			_ = tcp.SetKeepAlive(true)
			_ = tcp.SetKeepAlivePeriod(30 * time.Second)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			opts := tunnel.ServerOptions{
				ConnectTimeout:  30 * time.Second,
				SendQueueSize:   1024,
				ReadBufferSize:  256 * 1024,
				WriteBufferSize: 256 * 1024,
				Logger:          logger,
			}
			sess := tunnel.NewServerSession(conn, tlsCfg, users, opts)
			sess.Run(ctx)
		}()
	}

	wg.Wait()
	logger.Info("server stopped")
	return 0
}

// --- ClientCmd ---

// ClientCmd is the `smtp-tunnel-go client` subcommand. It connects to the
// server and runs a local SOCKS5 proxy.
type ClientCmd struct {
	ConfigPath string
	// CLI overrides.
	ServerHost  string
	ServerPort  int
	SocksHost   string
	SocksPort   int
	Username    string
	Secret      string
	CACert      string
	Debug       bool
	NoReconnect bool
}

func (c *ClientCmd) ParseFlags(args []string) {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	fs.StringVar(&c.ConfigPath, "config", "config.yaml", "config file")
	fs.StringVar(&c.ConfigPath, "c", "config.yaml", "config file (shorthand)")
	fs.StringVar(&c.ServerHost, "server", "", "server domain (override config)")
	fs.IntVar(&c.ServerPort, "server-port", 0, "server port (override config)")
	fs.StringVar(&c.SocksHost, "socks-host", "", "local SOCKS5 bind host (override config)")
	fs.IntVar(&c.SocksPort, "socks-port", 0, "local SOCKS5 port (override config)")
	fs.IntVar(&c.SocksPort, "p", 0, "local SOCKS5 port (shorthand)")
	fs.StringVar(&c.Username, "username", "", "username (override config)")
	fs.StringVar(&c.Username, "u", "", "username (shorthand)")
	fs.StringVar(&c.Secret, "secret", "", "secret (override config)")
	fs.StringVar(&c.Secret, "s", "", "secret (shorthand)")
	fs.StringVar(&c.CACert, "ca-cert", "", "CA certificate path (override config)")
	fs.BoolVar(&c.Debug, "debug", false, "enable debug logging")
	fs.BoolVar(&c.Debug, "d", false, "enable debug logging (shorthand)")
	fs.BoolVar(&c.NoReconnect, "no-reconnect", false, "exit instead of reconnecting on connection loss")
	_ = fs.Parse(args)
}

func (c *ClientCmd) Run(ctx context.Context) int {
	logLevel := slog.LevelInfo
	if c.Debug {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	// Load config (if present). Missing config is fine — the CLI flags
	// can supply everything.
	cfg, err := config.Load(c.ConfigPath)
	if err != nil && !os.IsNotExist(err) {
		// A parse error is fatal; a missing file is not.
		if _, isParse := err.(*os.PathError); !isParse {
			logger.Warn("parse config failed; ignoring", "path", c.ConfigPath, "err", err)
		}
		cfg = &config.File{}
	}

	// Apply overrides.
	if c.ServerHost != "" {
		cfg.Client.ServerHost = c.ServerHost
	}
	if c.ServerPort != 0 {
		cfg.Client.ServerPort = c.ServerPort
	}
	if c.SocksHost != "" {
		cfg.Client.SocksHost = c.SocksHost
	}
	if c.SocksPort != 0 {
		cfg.Client.SocksPort = c.SocksPort
	}
	if c.Username != "" {
		cfg.Client.Username = c.Username
	}
	if c.Secret != "" {
		cfg.Client.Secret = c.Secret
	}
	if c.CACert != "" {
		cfg.Client.CACert = c.CACert
	}

	if cfg.Client.ServerHost == "" {
		logger.Error("--server is required (or set client.server_host in config)")
		return 1
	}
	if cfg.Client.Username == "" {
		logger.Error("--username is required (or set client.username in config)")
		return 1
	}
	if cfg.Client.Secret == "" {
		logger.Error("--secret is required (or set client.secret in config)")
		return 1
	}

	// Construct the tunnel client.
	client, err := tunnel.NewClient(tunnel.ClientOptions{
		ServerHost:      cfg.Client.ServerHost,
		ServerPort:      cfg.Client.ServerPort,
		Username:        cfg.Client.Username,
		Secret:          cfg.Client.Secret,
		CACertPath:      cfg.Client.CACert,
		SendQueueSize:   1024,
		ReadBufferSize:  256 * 1024,
		WriteBufferSize: 256 * 1024,
		ConnectTimeout:  30 * time.Second,
		Logger:          logger,
	})
	if err != nil {
		logger.Error("init client failed", "err", err)
		return 1
	}

	// Construct the SOCKS5 server. We start it once and keep it running
	// for the whole lifetime of the process — even when the tunnel is
	// briefly disconnected, the SOCKS5 listener stays up so apps don't
	// see a connection refused. New SOCKS5 conns that arrive during a
	// disconnect window will simply fail-fast in handle().
	socks := socks5.New(client, socks5.ServerOptions{
		Host: cfg.Client.SocksHost,
		Port: cfg.Client.SocksPort,
		Logger: logger,
	})

	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// SOCKS5 listener runs in its own goroutine and lives for the
	// lifetime of the process.
	socksErr := make(chan error, 1)
	go func() {
		socksErr <- socks.Start(ctx)
	}()

	// Tunnel supervisor: connect, reconnect on loss.
	onConnect := func() {
		logger.Info("connected",
			"server", fmt.Sprintf("%s:%d", cfg.Client.ServerHost, cfg.Client.ServerPort))
		logger.Info("socks5 ready",
			"addr", fmt.Sprintf("%s:%d", cfg.Client.SocksHost, cfg.Client.SocksPort))
	}
	onDisconnect := func() {
		logger.Info("disconnected, reconnecting")
	}

	if c.NoReconnect {
		// Single-shot mode: connect once, exit on loss.
		if err := client.Connect(ctx); err != nil {
			logger.Error("connect failed", "err", err)
			return 1
		}
		onConnect()
		client.Wait()
		onDisconnect()
		return 0
	}

	client.RunForever(ctx, onConnect, onDisconnect)
	return 0
}

// --- GenCertsCmd ---

// GenCertsCmd is the `smtp-tunnel-go gencerts` subcommand. It generates
// the CA + server cert pair used by the server.
type GenCertsCmd struct {
	Hostname string
	OutDir   string
	Days     int
	RSA      bool
	RSABits  int
}

func (c *GenCertsCmd) ParseFlags(args []string) {
	fs := flag.NewFlagSet("gencerts", flag.ContinueOnError)
	fs.StringVar(&c.Hostname, "hostname", "mail.example.com", "certificate hostname")
	fs.StringVar(&c.OutDir, "output-dir", ".", "output directory")
	fs.StringVar(&c.OutDir, "o", ".", "output directory (shorthand)")
	fs.IntVar(&c.Days, "days", 1095, "certificate validity in days")
	fs.BoolVar(&c.RSA, "rsa", false, "use RSA keys (default: ECDSA P-256)")
	fs.IntVar(&c.RSABits, "rsa-bits", 2048, "RSA key size (only with -rsa)")
	_ = fs.Parse(args)
}

// runGenCerts is in cli/server.go for historical reasons — could be its
// own file. It's invoked by GenCertsCmd.Run (defined in gencerts.go).
func (c *GenCertsCmd) Run(ctx context.Context) int {
	return runGenCerts(c)
}

// --- helpers shared across subcommands ---

// resolvePath makes a path absolute relative to the current working
// directory. Used so that users can pass relative paths in CLI flags
// without surprises.
func resolvePath(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}

// suppressUnused keeps io / runtime / http imports alive for future
// expansion (admin/metrics endpoints). Remove if this becomes
// permanently unused.
var _ = io.Discard
var _ = runtime.NumCPU
var _ = http.StatusOK
