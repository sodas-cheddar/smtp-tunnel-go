package cli

import (
        "context"
        "flag"
        "fmt"
        "io"
        "log/slog"
        "os"
        "path/filepath"
        "strings"

        "github.com/sodas-cheddar/smtp-tunnel-go/internal/auth"
        "github.com/sodas-cheddar/smtp-tunnel-go/internal/config"
)

// AddUserCmd is the `smtp-tunnel-go adduser` subcommand. It creates a
// user in users.yaml and optionally generates a client ZIP package.
type AddUserCmd struct {
        Username   string
        Secret     string
        Whitelist  []string
        NoLogging  bool
        UsersPath  string
        ConfigPath string
        OutputDir  string
        NoPackage  bool
}

func (c *AddUserCmd) ParseFlags(args []string) error {
        fs := flag.NewFlagSet("adduser", flag.ContinueOnError)
        var whitelist repeatedString
        fs.Var(&whitelist, "whitelist", "IP whitelist entry (can be repeated); supports CIDR")
        fs.Var(&whitelist, "w", "IP whitelist entry (shorthand)")
        fs.StringVar(&c.Secret, "secret", "", "secret (auto-generated if not provided)")
        fs.StringVar(&c.Secret, "s", "", "secret (shorthand)")
        fs.BoolVar(&c.NoLogging, "no-logging", false, "disable logging for this user")
        fs.StringVar(&c.UsersPath, "users-file", "/etc/smtp-tunnel/users.yaml", "users file")
        fs.StringVar(&c.UsersPath, "u", "/etc/smtp-tunnel/users.yaml", "users file (shorthand)")
        fs.StringVar(&c.ConfigPath, "config", "/etc/smtp-tunnel/config.yaml", "server config file")
        fs.StringVar(&c.ConfigPath, "c", "/etc/smtp-tunnel/config.yaml", "server config file (shorthand)")
        fs.StringVar(&c.OutputDir, "output-dir", ".", "output directory for ZIP file")
        fs.StringVar(&c.OutputDir, "o", ".", "output directory (shorthand)")
        fs.BoolVar(&c.NoPackage, "no-package", false, "do not generate client ZIP package")
        // Allow positional args (username) to appear before flags, e.g.
        // `adduser alice -u file`. Go's flag package stops at the first
        // non-flag arg, so we manually reorder: collect non-flags into
        // positional and pass the rest to fs.Parse.
        args = reorderArgs(args)
        if err := fs.Parse(args); err != nil {
                return err
        }
        c.Whitelist = whitelist
        if fs.NArg() < 1 {
                return fmt.Errorf("adduser: username is required")
        }
        c.Username = fs.Arg(0)
        return nil
}

// reorderArgs moves non-flag arguments to the end so the Go flag package
// (which stops at the first non-flag) can still parse flags that come
// after the positional argument. e.g. `adduser alice -u file` becomes
// `adduser -u file alice`.
//
// We treat anything that doesn't start with "-" as positional. Values
// following a flag that takes a value (e.g. "-u file") are left in place
// because they don't start with "-". This is a heuristic but covers all
// our use cases.
func reorderArgs(args []string) []string {
        var flags, positional []string
        i := 0
        for i < len(args) {
                a := args[i]
                if a == "--" {
                        // Everything after -- is positional.
                        positional = append(positional, args[i+1:]...)
                        break
                }
                if strings.HasPrefix(a, "-") && a != "-" {
                        flags = append(flags, a)
                        // If this is a flag that takes a value and the value is in
                        // the next arg (i.e. the flag uses ' ' separator not '='),
                        // pull it in too.
                        if !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
                                flags = append(flags, args[i+1])
                                i += 2
                                continue
                        }
                } else {
                        positional = append(positional, a)
                }
                i++
        }
        return append(flags, positional...)
}

// repeatedString is a flag.Value that collects multiple -flag value
// invocations into a slice.
type repeatedString []string

func (r *repeatedString) String() string { return strings.Join(*r, ",") }
func (r *repeatedString) Set(v string) error {
        *r = append(*r, v)
        return nil
}

func (c *AddUserCmd) Run(ctx context.Context) int {
        logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

        usersPath := resolvePath(c.UsersPath)
        users, err := config.LoadUsers(usersPath)
        if err != nil {
                logger.Error("load users failed", "path", usersPath, "err", err)
                return 1
        }
        if _, exists := users[c.Username]; exists {
                fmt.Fprintf(os.Stderr, "Error: user '%s' already exists\n", c.Username)
                return 1
        }

        secret := c.Secret
        if secret == "" {
                secret = auth.GenerateSecret()
        }

        users[c.Username] = &config.UserConfig{
                Username:  c.Username,
                Secret:    secret,
                Whitelist: c.Whitelist,
                Logging:   !c.NoLogging,
        }
        if err := config.SaveUsers(usersPath, users); err != nil {
                logger.Error("save users failed", "err", err)
                return 1
        }
        fmt.Printf("User '%s' added to %s\n", c.Username, usersPath)

        if c.NoPackage {
                return 0
        }

        // Load server config to learn hostname + port for the client config.
        cfg, err := config.Load(c.ConfigPath)
        if err != nil {
                fmt.Fprintf(os.Stderr, "Warning: could not load %s: %v\n", c.ConfigPath, err)
                cfg = &config.File{}
        }
        serverHost := cfg.Server.Hostname
        if serverHost == "" {
                serverHost = "localhost"
        }
        serverPort := cfg.Server.Port
        if serverPort == 0 {
                serverPort = 587
        }

        outDir := resolvePath(c.OutputDir)
        zipPath, err := buildClientPackage(c.Username, secret, serverHost, serverPort, outDir)
        if err != nil {
                fmt.Fprintf(os.Stderr, "Warning: client package build failed: %v\n", err)
                return 0
        }
        fmt.Printf("Client package created: %s\n", zipPath)
        fmt.Println()
        fmt.Println("Send this ZIP file to the user. They just need to:")
        fmt.Println("  1. Extract the ZIP")
        fmt.Println("  2. Run the launcher (start.bat on Windows, ./start.sh on Linux/Mac)")
        return 0
}

// DelUserCmd is the `smtp-tunnel-go deluser` subcommand.
type DelUserCmd struct {
        Username   string
        UsersPath  string
        Force      bool
}

func (c *DelUserCmd) ParseFlags(args []string) error {
        fs := flag.NewFlagSet("deluser", flag.ContinueOnError)
        fs.StringVar(&c.UsersPath, "users-file", "/etc/smtp-tunnel/users.yaml", "users file")
        fs.StringVar(&c.UsersPath, "u", "/etc/smtp-tunnel/users.yaml", "users file (shorthand)")
        fs.BoolVar(&c.Force, "force", false, "do not ask for confirmation")
        fs.BoolVar(&c.Force, "f", false, "do not ask for confirmation (shorthand)")
        args = reorderArgs(args)
        if err := fs.Parse(args); err != nil {
                return err
        }
        if fs.NArg() < 1 {
                return fmt.Errorf("deluser: username is required")
        }
        c.Username = fs.Arg(0)
        return nil
}

func (c *DelUserCmd) Run(ctx context.Context) int {
        usersPath := resolvePath(c.UsersPath)
        users, err := config.LoadUsers(usersPath)
        if err != nil {
                fmt.Fprintf(os.Stderr, "Error: load users: %v\n", err)
                return 1
        }
        if _, exists := users[c.Username]; !exists {
                fmt.Fprintf(os.Stderr, "Error: user '%s' not found\n", c.Username)
                return 1
        }
        if !c.Force {
                fmt.Printf("Delete user '%s'? [y/N]: ", c.Username)
                var resp string
                fmt.Scanln(&resp)
                if strings.ToLower(resp) != "y" {
                        fmt.Println("Cancelled")
                        return 0
                }
        }
        delete(users, c.Username)
        if err := config.SaveUsers(usersPath, users); err != nil {
                fmt.Fprintf(os.Stderr, "Error: save users: %v\n", err)
                return 1
        }
        fmt.Printf("User '%s' removed\n", c.Username)
        zipPath := c.Username + ".zip"
        if _, err := os.Stat(zipPath); err == nil {
                fmt.Printf("Note: client package '%s' still exists - delete manually if needed\n", zipPath)
        }
        return 0
}

// ListUsersCmd is the `smtp-tunnel-go listusers` subcommand.
type ListUsersCmd struct {
        UsersPath string
        Verbose   bool
}

func (c *ListUsersCmd) ParseFlags(args []string) error {
        fs := flag.NewFlagSet("listusers", flag.ContinueOnError)
        fs.StringVar(&c.UsersPath, "users-file", "/etc/smtp-tunnel/users.yaml", "users file")
        fs.StringVar(&c.UsersPath, "u", "/etc/smtp-tunnel/users.yaml", "users file (shorthand)")
        fs.BoolVar(&c.Verbose, "verbose", false, "show detailed information")
        fs.BoolVar(&c.Verbose, "v", false, "show detailed information (shorthand)")
        if err := fs.Parse(args); err != nil {
                return err
        }
        return nil
}

func (c *ListUsersCmd) Run(ctx context.Context) int {
        usersPath := resolvePath(c.UsersPath)
        users, err := config.LoadUsers(usersPath)
        if err != nil {
                fmt.Fprintf(os.Stderr, "Error: load users: %v\n", err)
                return 1
        }
        if len(users) == 0 {
                fmt.Println("No users configured")
                fmt.Println("Use smtp-tunnel-go adduser <username> to add users")
                return 0
        }
        fmt.Printf("Users (%d):\n", len(users))
        fmt.Println(strings.Repeat("-", 60))
        // Stable order.
        names := make([]string, 0, len(users))
        for n := range users {
                names = append(names, n)
        }
        // sort
        for i := 0; i < len(names); i++ {
                for j := i + 1; j < len(names); j++ {
                        if names[j] < names[i] {
                                names[i], names[j] = names[j], names[i]
                        }
                }
        }
        for _, name := range names {
                u := users[name]
                if c.Verbose {
                        fmt.Printf("\n  %s:\n", name)
                        secret := u.Secret
                        if len(secret) > 12 {
                                secret = secret[:8] + "..." + secret[len(secret)-4:]
                        }
                        fmt.Printf("    Secret: %s\n", secret)
                        if len(u.Whitelist) > 0 {
                                fmt.Printf("    Whitelist: %s\n", strings.Join(u.Whitelist, ", "))
                        } else {
                                fmt.Println("    Whitelist: (any IP)")
                        }
                        fmt.Printf("    Logging: %s\n", boolStr(u.Logging))
                } else {
                        extras := ""
                        if len(u.Whitelist) > 0 {
                                extras += fmt.Sprintf(" [%d IPs]", len(u.Whitelist))
                        }
                        if !u.Logging {
                                extras += " [no-log]"
                        }
                        fmt.Printf("  %s%s\n", name, extras)
                }
        }
        if !c.Verbose {
                fmt.Println()
                fmt.Println("Use -v for detailed information")
        }
        return 0
}

func boolStr(b bool) string {
        if b {
                return "enabled"
        }
        return "disabled"
}

// buildClientPackage produces a ZIP containing the Go client binary,
// a config.yaml, ca.crt (if present), and launcher scripts.
//
// The Go client is a single static binary — far simpler to ship than
// the Python original which needed Python + pip + dependencies.
func buildClientPackage(username, secret, serverHost string, serverPort int, outDir string) (string, error) {
        if err := os.MkdirAll(outDir, 0o755); err != nil {
                return "", fmt.Errorf("mkdir outdir: %w", err)
        }

        tmpDir, err := os.MkdirTemp("", "smtp-tunnel-pkg-")
        if err != nil {
                return "", err
        }
        defer os.RemoveAll(tmpDir)

        pkgDir := filepath.Join(tmpDir, username)
        if err := os.MkdirAll(pkgDir, 0o755); err != nil {
                return "", err
        }

        // Build the Go client binary into the package directory. Cross-compile
        // for the host OS/arch by default. We deliberately don't try to be
        // clever about cross-compilation targets — the admin can always
        // `scp` the source and `go build` on the target machine.
        clientBinName := "smtp-tunnel-client"
        if hostOS() == "windows" {
                clientBinName = "smtp-tunnel-client.exe"
        }
        clientBinPath := filepath.Join(pkgDir, clientBinName)
        if err := buildClientBinary(clientBinPath); err != nil {
                return "", fmt.Errorf("build client binary: %w", err)
        }

        // Generate config.yaml for this user.
        cfgContent := fmt.Sprintf(`# SMTP Tunnel Client Configuration
# Generated for user: %s

client:
  server_host: "%s"
  server_port: %d
  socks_host: "127.0.0.1"
  socks_port: 1080
  username: "%s"
  secret: "%s"
  ca_cert: "ca.crt"
`, username, serverHost, serverPort, username, secret)
        if err := os.WriteFile(filepath.Join(pkgDir, "config.yaml"), []byte(cfgContent), 0o600); err != nil {
                return "", err
        }

        // Copy ca.crt if present in /etc/smtp-tunnel/.
        if caData, err := os.ReadFile("/etc/smtp-tunnel/ca.crt"); err == nil {
                _ = os.WriteFile(filepath.Join(pkgDir, "ca.crt"), caData, 0o644)
        } else {
                fmt.Fprintln(os.Stderr, "Warning: /etc/smtp-tunnel/ca.crt not found - client will not verify the server")
        }

        // Write a README.txt with usage instructions.
        readme := fmt.Sprintf(`SMTP Tunnel Client - %s

Quick Start
-----------

Linux / macOS:
  1. Extract this ZIP somewhere convenient.
  2. Run: ./start.sh
  3. Set your browser / apps to use SOCKS5 proxy 127.0.0.1:1080

Windows:
  1. Extract this ZIP somewhere convenient.
  2. Double-click start.bat
  3. Set your browser / apps to use SOCKS5 proxy 127.0.0.1:1080

Files
-----
  smtp-tunnel-client   The Go client binary (single file, no deps)
  config.yaml          Your config (pre-configured)
  ca.crt               Server CA cert for TLS verification
  start.sh             Linux/macOS launcher
  start.bat            Windows launcher
  README.txt           This file

Test Connection
---------------
  curl -x socks5h://127.0.0.1:1080 https://ifconfig.me

Should print your VPS IP address.

Troubleshooting
---------------
- "Auth failed"             -> check username/secret match server
- "Connection refused"      -> check server is up, port 587 open
- "Certificate verify ..."  -> ensure ca.crt is the server's CA cert

`, username)
        if err := os.WriteFile(filepath.Join(pkgDir, "README.txt"), []byte(readme), 0o644); err != nil {
                return "", err
        }

        // start.sh — Linux/macOS launcher.
        startSh := fmt.Sprintf(`#!/bin/bash
# SMTP Tunnel Client Launcher - User: %s
set -e
cd "$(dirname "$0")"

if [ ! -x ./smtp-tunnel-client ]; then
  chmod +x ./smtp-tunnel-client 2>/dev/null || true
fi

echo ""
echo "  SMTP Tunnel Proxy Client"
echo "  User: %s"
echo ""
echo "  SOCKS5 proxy will be available at 127.0.0.1:1080"
echo "  Press Ctrl+C to stop"
echo "  -------------------------------------------------------"
echo ""

exec ./smtp-tunnel-client -c config.yaml
`, username, username)
        if err := os.WriteFile(filepath.Join(pkgDir, "start.sh"), []byte(startSh), 0o755); err != nil {
                return "", err
        }

        // start.bat — Windows launcher.
        startBat := fmt.Sprintf(`@echo off
chcp 65001 >nul 2>&1
title SMTP Tunnel - %s
cd /d "%%~dp0"

echo.
echo   SMTP Tunnel Proxy Client
echo   User: %s
echo.
echo   SOCKS5 proxy will be available at 127.0.0.1:1080
echo   Press Ctrl+C to stop
echo   -------------------------------------------------------
echo.

smtp-tunnel-client.exe -c config.yaml

echo.
echo Connection closed. Press any key to exit...
pause >nul
`, username, username)
        if err := os.WriteFile(filepath.Join(pkgDir, "start.bat"), []byte(startBat), 0o644); err != nil {
                return "", err
        }

        // Zip it up.
        zipPath := filepath.Join(outDir, username+".zip")
        if err := zipDir(pkgDir, zipPath); err != nil {
                return "", fmt.Errorf("zip: %w", err)
        }
        return zipPath, nil
}

// io.Discard import placeholder (kept to avoid unused-import churn if
// we later move helpers around).
var _ = io.Discard
