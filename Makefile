# Makefile for smtp-tunnel-go
#
# Common targets:
#   make            - build both binaries into ./bin
#   make server     - build only the all-in-one server binary
#   make client     - build only the standalone client binary
#   make test       - run unit tests
#   make vet        - go vet
#   make clean      - remove build artifacts
#   make install    - install binaries to /usr/local/bin
#   make release    - cross-compile release binaries for all platforms
#   make package    - build a client ZIP package for distribution

GO ?= go
CGO_ENABLED ?= 0
LDFLAGS := -s -w
BUILD_FLAGS := -trimpath -ldflags '$(LDFLAGS)'

BINARY_SERVER := smtp-tunnel-go
BINARY_CLIENT := smtp-tunnel-client

BIN_DIR := bin
RELEASE_DIR := release

# Default: build both binaries
.PHONY: all
all: server client

.PHONY: server
server:
	@mkdir -p $(BIN_DIR)
	$(GO) build $(BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY_SERVER) ./cmd/$(BINARY_SERVER)

.PHONY: client
client:
	@mkdir -p $(BIN_DIR)
	$(GO) build $(BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY_CLIENT) ./cmd/$(BINARY_CLIENT)

.PHONY: test
test:
	$(GO) test -v -race ./...

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: clean
clean:
	rm -rf $(BIN_DIR) $(RELEASE_DIR)

.PHONY: install
install: all
	install -d /usr/local/bin
	install -m 0755 $(BIN_DIR)/$(BINARY_SERVER) /usr/local/bin/

# Cross-compile release binaries for all supported platforms.
# Output goes into ./release/<binary>-<os>-<arch>
.PHONY: release
release:
	@mkdir -p $(RELEASE_DIR)
	@for OS in linux darwin windows freebsd; do \
	  for ARCH in amd64 arm64 386 arm; do \
	    if [ "$$OS" = "darwin" ] && [ "$$ARCH" = "386" ]; then continue; fi; \
	    if [ "$$OS" = "darwin" ] && [ "$$ARCH" = "arm" ]; then continue; fi; \
	    if [ "$$OS" = "windows" ] && [ "$$ARCH" = "arm" ]; then continue; fi; \
	    echo "  -> $$OS/$$ARCH"; \
	    ext=""; if [ "$$OS" = "windows" ]; then ext=".exe"; fi; \
	    GOOS=$$OS GOARCH=$$ARCH CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) \
	      -o $(RELEASE_DIR)/$(BINARY_SERVER)-$$OS-$$ARCH$$ext ./cmd/$(BINARY_SERVER) || true; \
	    GOOS=$$OS GOARCH=$$ARCH CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) \
	      -o $(RELEASE_DIR)/$(BINARY_CLIENT)-$$OS-$$ARCH$$ext ./cmd/$(BINARY_CLIENT) || true; \
	  done; \
	done

# Build a client ZIP package (Linux amd64 by default; override with
# GOOS / GOARCH environment variables).
.PHONY: package
package: client
	@echo "Building client package for $$(go env GOOS)/$$(go env GOARCH)..."
	@./$(BIN_DIR)/$(BINARY_SERVER) adduser _package_temp \
	  --no-logging -o ./$(BIN_DIR) --no-package 2>/dev/null || true
	@echo "Client binary at: ./$(BIN_DIR)/$(BINARY_CLIENT)"
	@echo "Distribute this binary along with config.yaml and ca.crt."

# Build a Docker image (requires Docker).
.PHONY: docker
docker:
	docker build -t smtp-tunnel-go:latest .
