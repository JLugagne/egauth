module github.com/JLugagne/egauth/adapters/otel

go 1.26.7

toolchain go1.26.9

// The `replace` below resolves the core module from this repo's root so every go command works
// offline before the core tag exists. The `require` tracks the VERSION file (enforced by
// scripts/sync-versions.sh --check). At release the maintainer drops the replace and re-tidies
// against the published core tag; see RELEASING.md.

require (
	github.com/JLugagne/egauth v0.18.0-dev
	go.opentelemetry.io/otel v1.46.0
	go.opentelemetry.io/otel/sdk v1.46.0
	go.opentelemetry.io/otel/trace v1.46.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel/metric v1.46.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

replace github.com/JLugagne/egauth => ../..
