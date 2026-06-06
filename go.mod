module github.com/JLugagne/egauth

go 1.26

// The v0.1.0–v0.2.1 tags predate the public-release security hardening (insecure-by-default
// passkey, stale go directive, no tokens/basic). They are retracted so `go get` warns about and
// skips them once a version carrying this block (v0.3.0) is published.
retract (
	v0.2.1 // pre-public-hardening pre-release; superseded by v0.3.0
	v0.2.0 // pre-public-hardening pre-release; superseded by v0.3.0
	v0.1.0 // pre-public-hardening pre-release; superseded by v0.3.0
)

require (
	github.com/fxamacker/cbor/v2 v2.9.2
	github.com/go-webauthn/webauthn v0.17.4
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.0
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.52.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.2.6 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/sys v0.45.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
