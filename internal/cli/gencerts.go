package cli

import (
        "fmt"
        "log/slog"
        "os"

        "github.com/sodas-cheddar/smtp-tunnel-go/internal/certs"
)

// runGenCerts is the body of GenCertsCmd.Run.
func runGenCerts(c *GenCertsCmd) int {
        logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

        algo := certs.KeyECDSA
        if c.RSA {
                algo = certs.KeyRSA
        }

        fmt.Printf("Generating certificates for hostname: %s\n", c.Hostname)
        if c.RSA {
                fmt.Printf("Key: RSA-%d\n", c.RSABits)
        } else {
                fmt.Println("Key: ECDSA P-256")
        }
        fmt.Printf("Validity: %d days\n", c.Days)
        fmt.Println()

        if err := certs.Generate(certs.Options{
                Hostname: c.Hostname,
                OutDir:   c.OutDir,
                Days:     c.Days,
                KeyAlgo:  algo,
                RSABits:  c.RSABits,
        }); err != nil {
                logger.Error("cert generation failed", "err", err)
                return 1
        }

        fmt.Println()
        fmt.Println("Certificate generation complete!")
        fmt.Println()
        fmt.Printf("  ca.key         %s/ca.key\n", c.OutDir)
        fmt.Printf("  ca.crt         %s/ca.crt\n", c.OutDir)
        fmt.Printf("  server.key     %s/server.key\n", c.OutDir)
        fmt.Printf("  server.crt     %s/server.crt\n", c.OutDir)
        fmt.Println()
        fmt.Println("Server needs:  server.crt + server.key")
        fmt.Println("Client needs:  ca.crt (for verification)")
        return 0
}
