package cli

import (
        "archive/zip"
        "fmt"
        "io"
        "os"
        "os/exec"
        "path/filepath"
        "runtime"
)

// hostOS returns the GOOS string for the current host. Used to pick the
// right client binary name and launcher script.
func hostOS() string { return runtime.GOOS }

// buildClientBinary shells out to `go build` to produce a client
// binary at outPath. We do this rather than importing the client as a
// library so the resulting binary is a true standalone executable with
// no shared state, and so cross-compilation is as simple as setting
// GOOS/GOARCH in the admin's environment before running adduser.
//
// We rely on the GOPATH/GOFLAGS environment being set up by the
// admin's install step. If `go` is not on PATH we return an error
// that the caller can surface to the user.
func buildClientBinary(outPath string) error {
        // Find the project root by walking up from this source file. We
        // can't use runtime.Caller for that at build time of the *target*
        // binary — but we can look for go.mod relative to well-known
        // install paths.
        srcDirs := []string{
                "/opt/smtp-tunnel",     // standard install location
                ".",                    // cwd (admin running from source tree)
                "../..",                // ./internal/cli -> ../../
        }
        var projectRoot string
        for _, d := range srcDirs {
                if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
                        abs, err := filepath.Abs(d)
                        if err == nil {
                                projectRoot = abs
                                break
                        }
                }
        }
        if projectRoot == "" {
                return fmt.Errorf("could not locate project root (looked for go.mod in %v)", srcDirs)
        }

        cmd := exec.Command("go", "build",
                "-o", outPath,
                "-ldflags", "-s -w", // strip debug info for smaller binaries
                "./cmd/smtp-tunnel-client",
        )
        cmd.Dir = projectRoot
        cmd.Stdout = os.Stdout
        cmd.Stderr = os.Stderr
        cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
        if err := cmd.Run(); err != nil {
                return err
        }
        return nil
}

// zipDir walks srcDir recursively and writes every file it finds into a
// new ZIP archive at zipPath. The archive's path entries are relative to
// srcDir's parent (so the top-level dir name is preserved, matching the
// Python packaging behavior).
func zipDir(srcDir, zipPath string) error {
        fout, err := os.Create(zipPath)
        if err != nil {
                return err
        }
        defer fout.Close()

        zw := zip.NewWriter(fout)
        defer zw.Close()

        parent := filepath.Dir(srcDir)

        err = filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
                if err != nil {
                        return err
                }
                if info.IsDir() {
                        return nil
                }
                rel, err := filepath.Rel(parent, path)
                if err != nil {
                        return err
                }
                // ZIP paths always use forward slashes.
                arcName := filepath.ToSlash(rel)

                hdr, err := zip.FileInfoHeader(info)
                if err != nil {
                        return err
                }
                hdr.Name = arcName
                hdr.Method = zip.Deflate
                if info.Mode()&0o100 != 0 {
                        // Preserve executable bit on Unix.
                        hdr.SetMode(info.Mode())
                }

                w, err := zw.CreateHeader(hdr)
                if err != nil {
                        return err
                }
                in, err := os.Open(path)
                if err != nil {
                        return err
                }
                defer in.Close()
                _, err = io.Copy(w, in)
                return err
        })
        return err
}

// strings is used by zipDir — imported here so we don't shadow the
// package-level import in users.go.
