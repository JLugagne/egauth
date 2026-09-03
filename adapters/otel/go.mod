module github.com/JLugagne/egauth/adapters/otel

go 1.26.7

// The `replace` directive resolves the core module from this repo's root for local
// development. At release the maintainer removes it and re-tidies against the
// published core tag — see the two-tag dance in RELEASING.md.

require (
	github.com/JLugagne/egauth v0.8.2
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
	golang.org/x/sys v0.47.0 // indirect
)
