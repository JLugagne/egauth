.PHONY: all check verify vet lint lint-fix vulncheck test test-unit test-race test-e2e tidy ci sbom

# Pinned tool versions — keep in sync with .github/workflows/ci.yml
GOLANGCI_LINT_VERSION := v2.12.2
GOVULNCHECK_VERSION   := v1.1.4

# Multi-module monorepo: the core module (.) and the nested pgx adapter module (adapters/pgx).
# Core checks run with GOWORK=off so they exercise the standalone module external consumers get
# (no Docker, no workspace). Adapter checks run with the workspace active (default GOWORK=auto, the
# committed go.work) so the unpublished core module resolves from local disk.
ADAPTER := adapters/pgx

# ─── Default ──────────────────────────────────────────────────────────────────

# Default target — mirrors what CI runs (minus Docker integration tests).
all: check

# Full local quality gate: verify → vet → vulncheck → lint → unit tests.
# Equivalent to `make ci` but without the Docker-backed integration suite.
check: verify vet vulncheck lint test-unit

# Full CI gate including integration tests (requires Docker).
ci: verify vet vulncheck lint test

# ─── Dependencies ─────────────────────────────────────────────────────────────

# Tidy both modules and update go.sum files.
tidy:
	@echo "==> Tidying core module..."
	go mod tidy
	@echo "==> Tidying $(ADAPTER) module..."
	cd $(ADAPTER) && go mod tidy

# Verify checksums in go.sum match the module cache.
verify:
	@echo "==> Verifying dependencies (core)..."
	GOWORK=off go mod verify
	@echo "==> Verifying dependencies ($(ADAPTER))..."
	cd $(ADAPTER) && go mod verify

# ─── Code quality ─────────────────────────────────────────────────────────────

vet:
	@echo "==> Running go vet (core)..."
	GOWORK=off go vet ./...
	@echo "==> Running go vet ($(ADAPTER))..."
	cd $(ADAPTER) && go vet ./...

# Run golangci-lint (fails on issues — mirrors CI).
lint:
	@echo "==> Running golangci-lint (core)..."
	GOWORK=off go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --timeout=5m
	@echo "==> Running golangci-lint ($(ADAPTER))..."
	cd $(ADAPTER) && go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --timeout=5m

# Run golangci-lint with --fix to auto-correct fixable issues.
lint-fix:
	@echo "==> Running golangci-lint --fix (core)..."
	GOWORK=off go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --fix --timeout=5m
	@echo "==> Running golangci-lint --fix ($(ADAPTER))..."
	cd $(ADAPTER) && go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --fix --timeout=5m

vulncheck:
	@echo "==> Running govulncheck (core)..."
	GOWORK=off go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...
	@echo "==> Running govulncheck ($(ADAPTER))..."
	cd $(ADAPTER) && go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

# ─── Tests ────────────────────────────────────────────────────────────────────

# Full test suite including Docker-backed testcontainers tests.
test:
	@echo "==> Running tests (core, no Docker)..."
	GOWORK=off go test -race -failfast ./...
	@echo "==> Running tests ($(ADAPTER), Docker/testcontainers)..."
	cd $(ADAPTER) && go test -race -failfast ./...

# Docker-less unit tests: -short skips every testcontainers test.
# Use this when Docker is not available locally or in lightweight CI jobs.
test-unit:
	@echo "==> Running unit tests (core, -short, no Docker)..."
	GOWORK=off go test -short ./...
	@echo "==> Running unit tests ($(ADAPTER), -short, no Docker)..."
	cd $(ADAPTER) && go test -short ./...

# Race-detector unit tests (no Docker). Slower than test-unit but catches data races.
test-race:
	@echo "==> Running tests with race detector (core, -short)..."
	GOWORK=off go test -race -short ./...
	@echo "==> Running tests with race detector ($(ADAPTER), -short)..."
	cd $(ADAPTER) && go test -race -short ./...

# e2e security tests only (core module, no Docker, no -short).
test-e2e:
	@echo "==> Running e2e-security tests..."
	GOWORK=off go test -race -v ./e2e-security/...

# ─── Release ──────────────────────────────────────────────────────────────────

# Generate SBOM (Software Bill of Materials) for release.
# Usage: make sbom VERSION=vX.Y.Z
sbom:
	@if [ -z "$(VERSION)" ]; then echo "Usage: make sbom VERSION=vX.Y.Z"; exit 1; fi
	@echo "==> Generating SBOM for github.com/JLugagne/egauth@$(VERSION)..."
	go install github.com/anchore/syft@latest
	syft -o cyclonedx-json github.com/JLugagne/egauth@$(VERSION) > libauth-$(VERSION).sbom.json
	syft -o cyclonedx github.com/JLugagne/egauth@$(VERSION) > libauth-$(VERSION).sbom.xml
	@echo "==> SBOM generated: libauth-$(VERSION).sbom.json and libauth-$(VERSION).sbom.xml"
	@echo "==> Attach these files to the GitHub release using: gh release upload $(VERSION) libauth-$(VERSION).sbom.*"
