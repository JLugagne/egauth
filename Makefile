.PHONY: all verify vet lint vulncheck test test-unit check

# Pinned tool versions — keep in sync with .github/workflows/ci.yml
GOLANGCI_LINT_VERSION := v2.12.2
GOVULNCHECK_VERSION   := v1.1.4

# Multi-module monorepo: the core module (.) and the nested pgx adapter module (adapters/pgx).
# Core checks run with GOWORK=off so they exercise the standalone module external consumers get
# (no Docker, no workspace). Adapter checks run with the workspace active (default GOWORK=auto, the
# committed go.work) so the unpublished core module resolves from local disk.
ADAPTER := adapters/pgx

# Default target runs all checks locally
all: check

check: verify vet vulncheck lint test

verify:
	@echo "==> Verifying dependencies (core)..."
	GOWORK=off go mod verify
	@echo "==> Verifying dependencies ($(ADAPTER))..."
	cd $(ADAPTER) && go mod verify

vet:
	@echo "==> Running go vet (core)..."
	GOWORK=off go vet ./...
	@echo "==> Running go vet ($(ADAPTER))..."
	cd $(ADAPTER) && go vet ./...

lint:
	@echo "==> Running golangci-lint (core)..."
	GOWORK=off go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --timeout=5m
	@echo "==> Running golangci-lint ($(ADAPTER))..."
	cd $(ADAPTER) && go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --timeout=5m

vulncheck:
	@echo "==> Running govulncheck (core)..."
	GOWORK=off go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...
	@echo "==> Running govulncheck ($(ADAPTER))..."
	cd $(ADAPTER) && go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

test:
	@echo "==> Running tests (core, no Docker)..."
	GOWORK=off go test -race -failfast ./...
	@echo "==> Running tests ($(ADAPTER), Docker/testcontainers)..."
	cd $(ADAPTER) && go test -race -failfast ./...

# Docker-less unit tests: runs both modules with -short so every testcontainers test skips.
# Use this when you don't have Docker running; `make test` runs the full Docker-backed suite.
test-unit:
	@echo "==> Running unit tests (core, -short, no Docker)..."
	GOWORK=off go test -short ./...
	@echo "==> Running unit tests ($(ADAPTER), -short, no Docker)..."
	cd $(ADAPTER) && go test -short ./...

# Generate SBOM (Software Bill of Materials) for release
# Generates both JSON and XML formats using syft tool
# Usage: make sbom VERSION=vX.Y.Z
sbom:
	@if [ -z "$(VERSION)" ]; then echo "Usage: make sbom VERSION=vX.Y.Z"; exit 1; fi
	@echo "==> Generating SBOM for github.com/JLugagne/egauth@$(VERSION)..."
	go install github.com/anchore/syft@latest
	syft -o cyclonedx-json github.com/JLugagne/egauth@$(VERSION) > libauth-$(VERSION).sbom.json
	syft -o cyclonedx github.com/JLugagne/egauth@$(VERSION) > libauth-$(VERSION).sbom.xml
	@echo "==> SBOM generated: libauth-$(VERSION).sbom.json and libauth-$(VERSION).sbom.xml"
	@echo "==> Attach these files to the GitHub release using: gh release upload $(VERSION) libauth-$(VERSION).sbom.*"
