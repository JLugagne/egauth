.PHONY: all verify vet lint vulncheck gosec test test-unit check

# Pinned tool versions — keep in sync with .github/workflows/ci.yml
GOLANGCI_LINT_VERSION := v2.12.2
GOVULNCHECK_VERSION   := v1.6.0
GOSEC_VERSION         := v2.28.0

# Multi-module monorepo: the core module (.) and two nested adapter modules (adapters/pgx,
# adapters/otel). Core checks run with GOWORK=off so they exercise the standalone module external
# consumers get (no Docker, no workspace). Adapter checks run with the workspace active (default
# GOWORK=auto, the committed go.work) so the core module resolves from local disk.
ADAPTERS := adapters/pgx adapters/otel

# Default target runs all checks locally
all: check

check: verify vet vulncheck lint gosec test

verify:
	@echo "==> Verifying dependencies (core)..."
	GOWORK=off go mod verify
	@for d in $(ADAPTERS); do \
		echo "==> Verifying dependencies ($$d)..."; \
		(cd $$d && go mod verify) || exit 1; \
	done

vet:
	@echo "==> Running go vet (core)..."
	GOWORK=off go vet ./...
	@for d in $(ADAPTERS); do \
		echo "==> Running go vet ($$d)..."; \
		(cd $$d && go vet ./...) || exit 1; \
	done

lint:
	@echo "==> Running golangci-lint (core)..."
	GOWORK=off go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --timeout=5m
	@for d in $(ADAPTERS); do \
		echo "==> Running golangci-lint ($$d)..."; \
		(cd $$d && go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --timeout=5m) || exit 1; \
	done

vulncheck:
	@echo "==> Running govulncheck (core)..."
	GOWORK=off go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...
	@for d in $(ADAPTERS); do \
		echo "==> Running govulncheck ($$d)..."; \
		(cd $$d && go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...) || exit 1; \
	done

# gosec: Go-specific security-pattern SAST (weak crypto, missing cookie/server hardening, command
# injection shapes, etc.), complementing golangci-lint/govulncheck. See ci.yml's sast-gosec job
# for the excluded-rule rationale (kept in sync with the flags below).
gosec:
	@echo "==> Running gosec (core)..."
	GOWORK=off go run github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION) -exclude=G101,G124,G401,G505 -exclude-rules="internal/doctest/.*:G204,G304" ./...
	@for d in $(ADAPTERS); do \
		echo "==> Running gosec ($$d)..."; \
		(cd $$d && go run github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION) -exclude=G101,G124,G401,G505 ./...) || exit 1; \
	done

test:
	@echo "==> Running tests (core, no Docker)..."
	GOWORK=off go test -race -failfast ./...
	@echo "==> Running tests (adapters/pgx, Docker/testcontainers)..."
	cd adapters/pgx && go test -race -failfast ./...
	@echo "==> Running tests (adapters/otel)..."
	cd adapters/otel && go test -race ./...

# Docker-less unit tests: runs every module with -short so every testcontainers test skips.
# Use this when you don't have Docker running; `make test` runs the full Docker-backed suite.
test-unit:
	@echo "==> Running unit tests (core, -short, no Docker)..."
	GOWORK=off go test -short ./...
	@for d in $(ADAPTERS); do \
		echo "==> Running unit tests ($$d, -short, no Docker)..."; \
		(cd $$d && go test -short ./...) || exit 1; \
	done

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
