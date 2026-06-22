// Package certs generates a self-signed CA and a server certificate signed
// by that CA. The output files (ca.key, ca.crt, server.key, server.crt)
// match what the Python generate_certs.py script produces, so they can be
// used interchangeably.
//
// We use ECDSA P-256 by default — it is dramatically faster than RSA at
// the same security level and produces much smaller handshakes. RSA is
// still supported via the KeyRSA flag for environments that require it.
package certs

import (
        "crypto/ecdsa"
        "crypto/elliptic"
        "crypto/rand"
        "crypto/rsa"
        "crypto/x509"
        "crypto/x509/pkix"
        "encoding/pem"
        "fmt"
        "math/big"
        "net"
        "os"
        "path/filepath"
        "time"
)

// KeyAlgo identifies the algorithm used to generate the certificate key.
type KeyAlgo int

const (
        KeyECDSA KeyAlgo = iota // default — P-256
        KeyRSA                  // 2048-bit, for legacy compatibility
)

// Options controls cert generation.
type Options struct {
        Hostname  string // CN + SAN DNS name (e.g. "mail.example.com")
        OutDir    string // directory to write ca.key/ca.crt/server.key/server.crt
        Days      int    // server cert validity (default 1095 = 3y)
        KeyAlgo   KeyAlgo
        RSABits   int // used when KeyAlgo == KeyRSA (default 2048)
}

// Generate creates the CA and server cert/key files described by opts.
// The CA cert validity is 10x the server cert validity.
func Generate(opts Options) error {
        if opts.Hostname == "" {
                return fmt.Errorf("certs: hostname is required")
        }
        if opts.OutDir == "" {
                opts.OutDir = "."
        }
        if opts.Days <= 0 {
                opts.Days = 1095
        }
        if opts.RSABits <= 0 {
                opts.RSABits = 2048
        }
        if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
                return fmt.Errorf("certs: mkdir: %w", err)
        }

        now := time.Now()
        // CA cert validity = 10x server cert validity. The Python original
        // does `days_valid=args.days*10` for the CA, so we match that.
        caValidity := time.Duration(opts.Days*10) * 24 * time.Hour
        srvValidity := time.Duration(opts.Days) * 24 * time.Hour
        caNotAfter := now.Add(caValidity)
        srvNotAfter := now.Add(srvValidity)

        // ---- CA key + cert ----
        caKey, err := genKey(opts.KeyAlgo, opts.RSABits)
        if err != nil {
                return fmt.Errorf("certs: CA key: %w", err)
        }
        caTpl := &x509.Certificate{
                SerialNumber: randomSerial(),
                Subject: pkix.Name{
                        Country:            []string{"US"},
                        Province:           []string{"California"},
                        Locality:           []string{"San Francisco"},
                        Organization:       []string{"SMTP Tunnel"},
                        CommonName:         "SMTP Tunnel CA",
                },
                NotBefore:             now.Add(-time.Hour),
                NotAfter:              caNotAfter,
                IsCA:                  true,
                BasicConstraintsValid: true,
                MaxPathLen:            0,
                KeyUsage: x509.KeyUsage(
                        x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
                ),
        }
        caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, publicKey(caKey), caKey)
        if err != nil {
                return fmt.Errorf("certs: CA cert: %w", err)
        }

        // ---- Server key + cert ----
        srvKey, err := genKey(opts.KeyAlgo, opts.RSABits)
        if err != nil {
                return fmt.Errorf("certs: server key: %w", err)
        }

        sanDNS := []string{opts.Hostname, "localhost"}
        // Also include "smtp.<parent-domain>" like the Python script does.
        if i := indexOfDot(opts.Hostname); i > 0 {
                sanDNS = append(sanDNS, "smtp."+opts.Hostname[i+1:])
        }

        // If the hostname itself is an IP literal, add it as an IP SAN so
        // clients connecting by IP can verify the cert. This was a
        // long-standing limitation of the Python original; we fix it here.
        var sanIPs []net.IP
        if ip := net.ParseIP(opts.Hostname); ip != nil {
                sanIPs = append(sanIPs, ip)
        }
        // Always include 127.0.0.1 and ::1 so local testing "just works".
        sanIPs = append(sanIPs, net.IPv4(127, 0, 0, 1), net.IPv6loopback)

        srvTpl := &x509.Certificate{
                SerialNumber: randomSerial(),
                Subject: pkix.Name{
                        Country:      []string{"US"},
                        Province:     []string{"California"},
                        Locality:     []string{"San Francisco"},
                        Organization: []string{"Example Mail Services"},
                        CommonName:   opts.Hostname,
                },
                NotBefore: now.Add(-time.Hour),
                NotAfter:  srvNotAfter,
                KeyUsage: x509.KeyUsage(
                        x509.KeyUsageDigitalSignature |
                                x509.KeyUsageKeyEncipherment,
                ),
                ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
                BasicConstraintsValid: true,
                DNSNames:              sanDNS,
                IPAddresses:           sanIPs,
        }
        srvDER, err := x509.CreateCertificate(rand.Reader, srvTpl, caTpl, publicKey(srvKey), caKey)
        if err != nil {
                return fmt.Errorf("certs: server cert: %w", err)
        }

        // ---- Write files ----
        if err := writeKey(filepath.Join(opts.OutDir, "ca.key"), caKey); err != nil {
                return err
        }
        if err := writeCert(filepath.Join(opts.OutDir, "ca.crt"), caDER); err != nil {
                return err
        }
        if err := writeKey(filepath.Join(opts.OutDir, "server.key"), srvKey); err != nil {
                return err
        }
        if err := writeCert(filepath.Join(opts.OutDir, "server.crt"), srvDER); err != nil {
                return err
        }
        return nil
}

func genKey(algo KeyAlgo, rsaBits int) (any, error) {
        switch algo {
        case KeyECDSA:
                return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
        case KeyRSA:
                return rsa.GenerateKey(rand.Reader, rsaBits)
        default:
                return nil, fmt.Errorf("unknown key algo %d", algo)
        }
}

func publicKey(k any) any {
        switch v := k.(type) {
        case *ecdsa.PrivateKey:
                return v.Public()
        case *rsa.PrivateKey:
                return v.Public()
        }
        return nil
}

func writeKey(path string, key any) error {
        der, err := x509.MarshalPKCS8PrivateKey(key)
        if err != nil {
                return fmt.Errorf("certs: marshal key: %w", err)
        }
        f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
        if err != nil {
                return fmt.Errorf("certs: open %s: %w", path, err)
        }
        defer f.Close()
        return pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func writeCert(path string, der []byte) error {
        f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
        if err != nil {
                return fmt.Errorf("certs: open %s: %w", path, err)
        }
        defer f.Close()
        return pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func randomSerial() *big.Int {
        max := new(big.Int).Lsh(big.NewInt(1), 128) // 128-bit serial
        n, err := rand.Int(rand.Reader, max)
        if err != nil {
                // Should never happen — fall back to a fixed but unique-ish value.
                return big.NewInt(time.Now().UnixNano())
        }
        return n
}

func indexOfDot(s string) int {
        for i := 0; i < len(s); i++ {
                if s[i] == '.' {
                        return i
                }
        }
        return -1
}
