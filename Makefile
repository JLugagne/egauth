.PHONY: all verify vet lint vulncheck test check

# Pinned tool versions — keep in sync with .github/workflows/ci.yml
GOLANGCI_LINT_VERSION := v2.12.2
GOVULNCHECK_VERSION   := v1.1.4

# Default target runs all checks locally
all: check

check: verify vet vulncheck lint test

verify:
	@echo "==> Verifying dependencies..."
	go mod verify

vet:
	@echo "==> Running go vet..."
	go vet ./...

lint:
	@echo "==> Running golangci-lint..."
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --timeout=5m

vulncheck:
	@echo "==> Running govulncheck..."
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

test:
	@echo "==> Running tests..."
	go test -race -failfast ./...
