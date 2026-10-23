module github.com/JLugagne/egauth

go 1.26.7

toolchain go1.26.10

// The v0.1.0–v0.2.1 tags predate the public-release security hardening (insecure-by-default
// passkey, stale go directive, no tokens/basic). They are retracted so `go get` warns about and
// skips them once a version carrying this block (v0.3.0) is published.
retract (
	v0.2.1 // pre-public-hardening pre-release; superseded by v0.3.0
	v0.2.0 // pre-public-hardening pre-release; superseded by v0.3.0
	v0.1.0 // pre-public-hardening pre-release; superseded by v0.3.0
)

require (
	github.com/fxamacker/cbor/v2 v2.9.6
	github.com/go-webauthn/webauthn v0.18.2
	github.com/google/uuid v1.6.0
	github.com/stretchr/testify v1.12.1
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.60.0
	golang.org/x/text v0.42.0
)

require (
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.3.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/tinylib/msgp v1.6.5 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/sys v0.48.0 // indirect
)
