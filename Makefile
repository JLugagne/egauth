.PHONY: all verify vet lint vulncheck test check

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
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run --timeout=5m

vulncheck:
	@echo "==> Running govulncheck..."
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

test:
	@echo "==> Running tests..."
	go test -race -failfast ./...
