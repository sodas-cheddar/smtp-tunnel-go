# Multi-stage build for smtp-tunnel-go
#
# Stage 1: build the binaries from source using the official Go image.
# Stage 2: copy just the binaries into a minimal distroless final image.
#
# The final image is ~20MB and has zero shell, package manager, or libc.
# Suitable for running the server in a container.

# ---- Build stage ----
FROM golang:1.22-alpine AS builder

WORKDIR /src

# Cache module downloads.
COPY go.mod go.sum ./
RUN go mod download

# Copy source.
COPY . .

# Build both binaries with stripped symbols and trimmed paths.
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags '-s -w' -o /out/smtp-tunnel-go ./cmd/smtp-tunnel-go && \
    go build -trimpath -ldflags '-s -w' -o /out/smtp-tunnel-client ./cmd/smtp-tunnel-client

# ---- Final stage ----
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/smtp-tunnel-go /usr/local/bin/smtp-tunnel-go
COPY --from=builder /out/smtp-tunnel-client /usr/local/bin/smtp-tunnel-client

# Default config directory.
COPY config.yaml.example /etc/smtp-tunnel/config.yaml

# SMTP submission port.
EXPOSE 587

# Run as non-root (distroless nonroot user).
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/smtp-tunnel-go"]
CMD ["server", "-c", "/etc/smtp-tunnel/config.yaml"]
