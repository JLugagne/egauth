.PHONY: all check verify vet lint lint-fix vulncheck test test-unit test-race test-e2e tidy ci sbom archtest doclint journey journey-full versions smoke test-otel test-tools

# Pinned tool versions. CI runs `make lint` and `make vulncheck`, so these are the single source;
# scripts/sync-versions.sh --check fails when ci.yml or RELEASING.md carry a different pin.
GOLANGCI_LINT_VERSION := v2.14.0
GOVULNCHECK_VERSION   := v1.8.0
# RELEASING.md repeats this pin (checked by sync-versions.sh). Update deliberately after reviewing the upstream release.
SYFT_VERSION          := v1.54.0
# Release-signing tools. These produce the artifacts consumers verify releases against, so they run
# with the maintainer's OIDC identity and full filesystem access: pin them, and review the upstream
# release before bumping. RELEASING.md repeats these pins (checked by sync-versions.sh).
GITSIGN_VERSION       := v0.17.1
COSIGN_VERSION        := v3.1.3

# Multi-module monorepo: the core module (.), the published adapters (adapters/pgx, adapters/otel)
# and the unpublished guard module (tools). Core checks run with GOWORK=off so they exercise the
# standalone module external consumers get (no Docker, no workspace). Adapter checks resolve core
# through the replace directive in their go.mod.
ADAPTER := adapters/pgx
OTEL    := adapters/otel

# ─── Default ──────────────────────────────────────────────────────────────────

# Default target — mirrors what CI runs (minus Docker integration tests).
all: check

# Full local quality gate: verify → vet → vulncheck → lint → guards → unit tests.
# Equivalent to `make ci` but without the Docker-backed integration suite.
check: verify vet vulncheck lint versions archtest doclint test-tools journey test-unit

# Full CI gate including integration tests (requires Docker): the full journey matrix with G7b,
# the pgx suites with adapters/pgx/e2e (G29 legacy upgrade), and the otel module.
ci: verify vet vulncheck lint versions archtest doclint test-tools journey-full test test-otel smoke

# ─── Dependencies ─────────────────────────────────────────────────────────────

# Tidy both modules and update go.sum files.
tidy:
	@echo "==> Tidying core module..."
	go mod tidy
	@echo "==> Tidying $(ADAPTER) module..."
	cd $(ADAPTER) && go mod tidy
	@echo "==> Tidying $(OTEL) module..."
	cd $(OTEL) && go mod tidy

# Verify checksums in go.sum match the module cache.
verify:
	@echo "==> Verifying dependencies (core)..."
	GOWORK=off go mod verify
	@echo "==> Verifying dependencies ($(ADAPTER))..."
	cd $(ADAPTER) && go mod verify
	@echo "==> Verifying dependencies ($(OTEL))..."
	cd $(OTEL) && go mod verify
	@echo "==> Verifying dependencies (tools)..."
	cd tools && GOWORK=off go mod verify

# ─── Code quality ─────────────────────────────────────────────────────────────

vet:
	@echo "==> Running go vet (core)..."
	GOWORK=off go vet ./...
	@echo "==> Running go vet ($(ADAPTER))..."
	cd $(ADAPTER) && go vet ./...
	@echo "==> Running go vet ($(OTEL))..."
	cd $(OTEL) && go vet ./...
	@echo "==> Running go vet (tools)..."
	cd tools && GOWORK=off go vet ./...

# Run golangci-lint (fails on issues — mirrors CI).
lint:
	@echo "==> Running golangci-lint (core)..."
	GOWORK=off go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --timeout=5m
	@echo "==> Running golangci-lint ($(ADAPTER))..."
	cd $(ADAPTER) && go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --timeout=5m
	@echo "==> Running golangci-lint ($(OTEL))..."
	cd $(OTEL) && go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --timeout=5m
	@echo "==> Running golangci-lint (tools)..."
	cd tools && GOWORK=off go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --timeout=5m

# Run golangci-lint with --fix to auto-correct fixable issues.
lint-fix:
	@echo "==> Running golangci-lint --fix (core)..."
	GOWORK=off go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --fix --timeout=5m
	@echo "==> Running golangci-lint --fix ($(ADAPTER))..."
	cd $(ADAPTER) && go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --fix --timeout=5m
	@echo "==> Running golangci-lint --fix ($(OTEL))..."
	cd $(OTEL) && go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --fix --timeout=5m

vulncheck:
	@echo "==> Running govulncheck (core)..."
	GOWORK=off go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...
	@echo "==> Running govulncheck ($(ADAPTER))..."
	cd $(ADAPTER) && go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...
	@echo "==> Running govulncheck ($(OTEL))..."
	cd $(OTEL) && go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

# ─── Guards ───────────────────────────────────────────────────────────────────

# Architecture guards (tools module). -count=1: the guards read repository files the test cache
# does not track.
archtest:
	@echo "==> Running architecture guards (tools/archtest)..."
	cd tools && GOWORK=off go test -count=1 ./archtest/...

doclint:
	@echo "==> Running doc lint (tools/doclint)..."
	cd tools && GOWORK=off go run ./doclint -check

# Unit tests of the guard module itself, minus archtest (run by the archtest target).
test-tools:
	@echo "==> Running tools unit tests..."
	cd tools && GOWORK=off go test -count=1 $$(GOWORK=off go list ./... | grep -v '/archtest')

# Short journey matrix (no Docker).
journey:
	@echo "==> Running journey matrix (short)..."
	GOWORK=off go test -short -timeout 20m ./internal/journeytest/...

# Full journey matrix including the G7b semantic opt-out guard (no Docker).
journey-full:
	@echo "==> Running full journey matrix and G7b..."
	GOWORK=off go test -count=1 -timeout 40m ./internal/journeytest/...

# G17: VERSION against every sibling require, CORE_VERSION and RELEASING.md.
versions:
	@echo "==> Checking version sync (G17)..."
	bash scripts/sync-versions.sh --check

# Consumer module graph across every published module (needs network for the warm-up).
smoke:
	@echo "==> Running consumer smoke..."
	bash scripts/consumer-smoke.sh

# ─── Tests ────────────────────────────────────────────────────────────────────

# Full test suite including Docker-backed testcontainers tests.
test:
	@echo "==> Running tests (core, no Docker; journeytest runs in journey-full)..."
	GOWORK=off go test -race -failfast -timeout 30m $$(GOWORK=off go list ./... | grep -v '/internal/journeytest$$')
	@echo "==> Running tests ($(ADAPTER), Docker/testcontainers, includes e2e and G29)..."
	cd $(ADAPTER) && go test -race -failfast -timeout 30m ./...

test-otel:
	@echo "==> Running tests ($(OTEL))..."
	cd $(OTEL) && go vet ./... && go test -race ./...

# Docker-less unit tests: -short skips every testcontainers test.
# Use this when Docker is not available locally or in lightweight CI jobs.
test-unit:
	@echo "==> Running unit tests (core, -short, no Docker)..."
	GOWORK=off go test -short -timeout 20m ./...
	@echo "==> Running unit tests ($(ADAPTER), -short, no Docker)..."
	cd $(ADAPTER) && go test -short ./...
	@echo "==> Running unit tests ($(OTEL))..."
	cd $(OTEL) && go test ./...

# Race-detector unit tests (no Docker). Slower than test-unit but catches data races.
test-race:
	@echo "==> Running tests with race detector (core, -short)..."
	GOWORK=off go test -race -short -timeout 30m ./...
	@echo "==> Running tests with race detector ($(ADAPTER), -short)..."
	cd $(ADAPTER) && go test -race -short ./...
	@echo "==> Running tests with race detector ($(OTEL))..."
	cd $(OTEL) && go test -race ./...

# pgx end-to-end suite (adapters/pgx/e2e, needs Docker; includes the G29 legacy upgrade test).
test-e2e:
	@echo "==> Running adapters/pgx/e2e..."
	cd $(ADAPTER) && go test -race -v ./e2e/...

# ─── Release ──────────────────────────────────────────────────────────────────

# Generate SBOM (Software Bill of Materials) for release.
# Usage: make sbom VERSION=vX.Y.Z
sbom:
	@if [ -z "$(VERSION)" ]; then echo "Usage: make sbom VERSION=vX.Y.Z"; exit 1; fi
	@echo "==> Generating SBOM for github.com/JLugagne/egauth@$(VERSION)..."
	go install github.com/anchore/syft/cmd/syft@$(SYFT_VERSION)
	@dir=""; \
	for attempt in 1 2 3 4 5 6 7 8 9 10; do \
	  GOWORK=off go mod download github.com/JLugagne/egauth@$(VERSION) >/dev/null 2>&1; \
	  dir=$$(GOWORK=off go list -m -f '{{.Dir}}' github.com/JLugagne/egauth@$(VERSION) 2>/dev/null); \
	  if [ -n "$$dir" ] && [ -d "$$dir" ]; then break; fi; \
	  echo "==> module $(VERSION) not resolvable yet (attempt $$attempt/10); retrying in 15s..."; \
	  sleep 15; \
	done; \
	if [ -z "$$dir" ] || [ ! -d "$$dir" ]; then echo "FAIL: could not resolve module source for $(VERSION) (is the tag published?)"; exit 1; fi; \
	MODULE=$$(GOWORK=off go list -m -f '{{.Path}}' github.com/JLugagne/egauth@$(VERSION)); \
	syft "dir:$$dir" --source-name "$$MODULE" --source-version "$(VERSION)" -o cyclonedx-json > libauth-$(VERSION).sbom.json; \
	syft "dir:$$dir" --source-name "$$MODULE" --source-version "$(VERSION)" -o cyclonedx > libauth-$(VERSION).sbom.xml
	@echo "==> SBOM generated: libauth-$(VERSION).sbom.json and libauth-$(VERSION).sbom.xml"
	@echo "==> Attach these files to the GitHub release using: gh release upload $(VERSION) libauth-$(VERSION).sbom.*"
