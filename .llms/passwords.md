# passwords — hashing / policy / breach-check seams + references

```
import (seams): github.com/JLugagne/egauth/passwords
argon2:         github.com/JLugagne/egauth/passwords/argon2
policy:         github.com/JLugagne/egauth/passwords/policy
breach (HIBP):  github.com/JLugagne/egauth/passwords/breach/hibp
breach (offline): github.com/JLugagne/egauth/passwords/breach/offline
source: passwords/*.go, passwords/argon2/*.go, passwords/policy/*.go, passwords/breach/**
```

## Purpose

Three seams `identity.NewService` consumes: `Hasher` (hash + constant-time compare), `Policy` (validate a candidate), `BreachChecker` (compromised-credential lookup). Plug in the shipped references or your own.

`MaxPasswordLength = 1024` bytes — hashers MUST reject input above this before invoking the KDF to prevent pre-auth CPU/memory amplification DoS.

## Seam interfaces

```go
// passwords package

type Hasher interface {
    Hash(ctx context.Context, password string) (string, error)
    Compare(ctx context.Context, hash, password string) error
}

type Policy interface {
    Verify(ctx context.Context, password string) error
}

type BreachChecker interface {
    IsBreached(ctx context.Context, password string) (bool, error)
}

// Adapter: wrap a plain function as BreachChecker
type BreachCheckerFunc func(ctx context.Context, password string) (bool, error)
func (f BreachCheckerFunc) IsBreached(ctx context.Context, password string) (bool, error)
```

## argon2 (reference Hasher)

```go
func NewHasher(opts ...Option) *Hasher
```

Defaults (OWASP 2021, highly-concurrent workload): `m=65536 KiB (64 MB)`, `t=1`, `p=4`, `keyLen=32`, `saltLen=16`. Output is PHC string format.

Cost floors (values below are clamped up silently):
- `MinMemoryKiB = 19456` (19 MiB)
- `MinTime = 1`
- `MinThreads = 1`

Verify-path ceilings (a STORED hash outside them is rejected as `ErrInvalidPassword` before the KDF runs, so one tampered/imported row cannot drive unbounded CPU or an OOM):
- `MaxMemoryKiB = 524288` (512 MiB)
- `MaxTime = 32` (iterations)
- `MaxThreads = 64` (parallelism)
- `MaxKeyLen = 1024` bytes (derived-key segment)
- `MaxSaltLen = 1024` bytes (salt segment)

The checks read only the stored hash's shape, never the candidate password.

Options:
```go
func WithMemory(memory uint32) Option   // KiB; clamped to MinMemoryKiB
func WithTime(time uint32) Option       // iterations; clamped to MinTime
func WithThreads(threads uint8) Option  // parallelism; clamped to MinThreads
```

Rehash-on-login (not part of `passwords.Hasher` interface — concrete method only):
```go
func (h *Hasher) NeedsRehash(hash string) bool
```
Returns `true` when any stored cost parameter is below the hasher's current target, or when the hash is malformed/foreign-format. Call after a successful `Compare`; if true, re-hash plaintext and persist. Performs no KDF work.

## policy

### DefaultPolicy (character-class rules)

```go
func NewDefaultPolicy() *DefaultPolicy
```

Defaults: `MinLength=8`, `MaxLength=72`, `RequireUppercase=true`, `RequireLowercase=true`, `RequireNumber=true`, `RequireSpecial=true`. Fields are exported — mutate directly after construction.

```go
func (p *DefaultPolicy) Verify(ctx context.Context, password string) error
```

Length measured in Unicode code points (runes), not bytes.

### PassphrasePolicy (NIST SP 800-63B)

```go
func NewPassphrasePolicy(opts ...PassphraseOption) *PassphrasePolicy
```

No character-class requirements. Enforces length + denylist + optional `BreachChecker`. Built-in minimal denylist of extremely common secrets.

Defaults: `MinLength=12`, `MaxLength=256`.

```go
func (p *PassphrasePolicy) Verify(ctx context.Context, password string) error
```

Options:
```go
func WithMinLength(n int) PassphraseOption
func WithMaxLength(n int) PassphraseOption        // 0 = no maximum
func WithDenylist(entries ...string) PassphraseOption  // case+whitespace insensitive; cumulative
func WithBreachChecker(b passwords.BreachChecker) PassphraseOption
```

Exported fields:
```go
type PassphrasePolicy struct {
    MinLength int  // Unicode code points
    MaxLength int  // 0 = no max
    // unexported: denylist, breachChecker
}
```

## breach checkers

### hibp (k-anonymity range API)

```go
func New(opts ...Option) *Client
func (c *Client) IsBreached(ctx context.Context, password string) (bool, error)
```

Only the first 5 hex chars of SHA-1(password) leave the process. Default fail posture: **fail closed** (upstream error propagates). Default HTTP timeout: 10s. Default threshold: 1 (any appearance = breached).

**Fail-open vs fail-closed is ultimately the consumer's posture decision, not just the client's.** `BreachChecker` is a hook — egauth makes no network calls itself, and the password policy **propagates a checker error unchanged**. So the *handler's* error handling decides the end-to-end posture: rejecting on any policy error = fail-closed (a breach-service outage blocks every registration/password-change); special-casing only `ErrPasswordBreached` and letting other errors pass = fail-open (an outage silently disables screening, can go unnoticed for months). No safe default — decide deliberately, wrap `IsBreached` in a **timeout**, and **log/alert on error** so a silent fail-open is observable. The hibp client's `WithFailOpen()` only sets the client's own posture; a custom checker or the handler's error mapping still governs the real outcome. Treat breach screening as advisory defence-in-depth on top of length+denylist, never the primary control.

Options:
```go
func WithHTTPClient(c *http.Client) Option   // custom transport/timeouts/proxies
func WithUserAgent(ua string) Option         // HIBP requires non-empty descriptive UA
func WithBaseURL(u string) Option            // default: https://api.pwnedpasswords.com
func WithThreshold(n int) Option             // min sighting count to treat as breached
func WithAddPadding(enabled bool) Option     // HIBP response padding header (default on)
func WithFailOpen() Option                   // on error return (false, nil) instead of err
```

### offline (in-memory set, no network)

```go
func LoadHashes(r io.Reader, opts ...Option) (*Checker, error)
func LoadPasswords(r io.Reader) (*Checker, error)
func (c *Checker) IsBreached(ctx context.Context, password string) (bool, error)
```

`LoadHashes`: reads newline-delimited lines; accepts bare 40-char hex SHA-1 or HIBP offline format `<HASH>:<count>`. Blank lines ignored. Hashes normalized to uppercase. A non-blank invalid line is an error.

`LoadPasswords`: reads newline-delimited plaintext secrets; hashes each with SHA-1. No counts.

Only error `IsBreached` can return: context cancellation.

Option:
```go
func WithThreshold(n int) Option  // min count in "<hash>:<count>" lines to load (default 1); no effect on LoadPasswords
```

## Errors

```go
// passwords package sentinels
var ErrPasswordTooShort     = errors.New("passwords: password is too short")
var ErrPasswordTooLong      = errors.New("passwords: password is too long")
var ErrPasswordMissingUppercase = errors.New("passwords: password must contain at least one uppercase letter")
var ErrPasswordMissingLowercase = errors.New("passwords: password must contain at least one lowercase letter")
var ErrPasswordMissingNumber    = errors.New("passwords: password must contain at least one number")
var ErrPasswordMissingSpecial   = errors.New("passwords: password must contain at least one special character")
var ErrPasswordBreached     = errors.New("passwords: password is known to be compromised")
var ErrInvalidPassword      = errors.New("passwords: invalid password")
var ErrHashFailed           = errors.New("passwords: failed to hash password")
```

`ErrPasswordBreached` is returned by `PassphrasePolicy.Verify` when the denylist or `BreachChecker` matches. `ErrInvalidPassword` is returned by `Hasher.Compare` on mismatch. `ErrHashFailed` on internal KDF failure.

## Wiring

```go
import (
    "github.com/JLugagne/egauth/identity"
    "github.com/JLugagne/egauth/passwords/argon2"
    "github.com/JLugagne/egauth/passwords/policy"
    "github.com/JLugagne/egauth/passwords/breach/hibp"
)

hasher := argon2.NewHasher()                    // defaults: 64 MB, t=1, p=4
// or tuned: argon2.NewHasher(argon2.WithMemory(131072), argon2.WithTime(2))

pol := policy.NewDefaultPolicy()                // character-class rules
// or NIST passphrase:
bc := hibp.New(hibp.WithUserAgent("myapp/1.0"))
pol := policy.NewPassphrasePolicy(
    policy.WithMinLength(16),
    policy.WithBreachChecker(bc),
)

svc := identity.NewService(store, hasher, pol)

// Rehash on login (argon2 only):
if err := hasher.Compare(ctx, storedHash, plaintext); err == nil {
    if hasher.NeedsRehash(storedHash) {
        newHash, _ := hasher.Hash(ctx, plaintext)
        store.UpdatePasswordHash(ctx, userID, newHash)
    }
}
```

## Gotchas

- **Argon2id cost tuning**: defaults (64 MB, t=1, p=4) target highly concurrent workloads. Raise `WithMemory`/`WithTime` for lower-concurrency, higher-security contexts. Any increase auto-triggers `NeedsRehash` for existing users on next login.
- **Breach check fail-open vs closed**: `hibp.New()` is fail-closed by default — a network outage rejects the login. Use `WithFailOpen()` to prioritize availability over screening coverage.
- **PassphrasePolicy vs DefaultPolicy**: `PassphrasePolicy` enforces no character classes (NIST 800-63B §5.1.1). Use it when you want length-first UX. `DefaultPolicy` retains classic composition rules.
- **`NeedsRehash` is not on the interface**: type-assert to `*argon2.Hasher` or hold the concrete type when rehash-on-login is needed.
- **`BreachChecker` receives plaintext**: implementations must never log or persist the password argument.
- **Length in runes**: both policies count Unicode code points, not bytes. The KDF DoS cap (`MaxPasswordLength = 1024`) is a byte limit applied inside hashers before the KDF runs.
