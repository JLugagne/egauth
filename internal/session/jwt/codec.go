// Package jwt is the JWT session backend: refresh families in tokens.Store and short-lived egv 2
// access tokens, plus the codec that resource servers verify those tokens with. It is the only
// package that signs or parses access tokens and the only place the "amr" claim is written; no
// decision is ever taken from amr (C-09, C-31, C-56).
package jwt

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/revoke"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/signing"
)

const (
	// TokenType is the JWS "typ" header and "typ" claim of every egauth access token (RFC 9068).
	TokenType = "at+jwt"
	// Version is the "egv" claim of the access-token format this package writes and accepts.
	Version = 2
	// MaxIssuedAtSkew is how far in the future an "iat" may lie before a token is refused.
	MaxIssuedAtSkew = 30 * time.Second
	// MaxTokenLen bounds an access token accepted for verification, in bytes.
	MaxTokenLen = 8192

	tenantMarker   = "{tenant}"
	maxFingerprint = 128
	maxUnixSeconds = 1 << 40
)

var (
	// ErrInvalidConfig reports a codec or backend configuration that cannot work.
	ErrInvalidConfig = errors.New("jwt: invalid configuration")
	// ErrInvalidToken reports an access token that is malformed, not signed by a key of its tenant
	// under that key's algorithm, of another format version, issuer, audience or claims type, or
	// whose claims disagree with its sealed attributes. A v0.16 token is one.
	ErrInvalidToken = errors.New("jwt: invalid access token")
	// ErrExpired reports an access token at or past its "exp".
	ErrExpired = errors.New("jwt: access token expired")
)

var b64 = base64.RawURLEncoding.Strict()

type signingOwner struct{}

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type claimSet struct {
	Iss      string          `json:"iss"`
	Aud      string          `json:"aud"`
	Sub      string          `json:"sub"`
	Tid      string          `json:"tid"`
	Sid      string          `json:"sid"`
	Iat      int64           `json:"iat"`
	Exp      int64           `json:"exp"`
	Typ      string          `json:"typ"`
	Egv      int             `json:"egv"`
	Egc      string          `json:"egc"`
	Att      string          `json:"att"`
	Apc      json.RawMessage `json:"apc"`
	AMR      []string        `json:"amr"`
	AuthTime int64           `json:"auth_time"`
}

// KeySource returns the key that verifies a tenant's tokens carrying a key id; keys.Manager
// satisfies it, and so does a resource server's JWKS. A failure joined with revoke.ErrUnavailable
// is an outage; any other error refuses the token.
type KeySource interface {
	Verifier(ctx context.Context, t principal.TenantID, kid string) (signing.Verifier, error)
}

// CodecConfig configures NewCodec. PublicOrigin is the deployment's origin, with at most one
// {tenant} host label; ClaimsFingerprint is the "egc" fingerprint of the application claims type.
// The zero Clock reads the wall clock.
type CodecConfig struct {
	PublicOrigin      string
	ClaimsFingerprint string
	RecheckEvery      time.Duration
	Clock             clock.Clock
}

// Codec encodes and verifies the egv 2 access tokens of one deployment. A token's key id pins its
// algorithm: the verifier refuses any other "alg" before any cryptography. It is safe for
// concurrent use.
type Codec struct {
	minter      *signing.Minter
	origin      string
	fingerprint string
	recheck     time.Duration
	clk         clock.Clock
}

// Token is a verified access token. Its attributes and claims are exactly those sealed at issue.
type Token struct {
	issuer    string
	audience  string
	family    uuid.UUID
	issuedAt  time.Time
	expiresAt time.Time
	attrs     core.SessionAttrs
	claims    core.SealedClaims
}

func (t Token) Issuer() string { return t.issuer }

// Audience returns the "aud" claim: the issuer for a session token, a resource audience otherwise.
func (t Token) Audience() string { return t.audience }

// Family returns the "sid" claim: the refresh family the token was minted for.
func (t Token) Family() uuid.UUID { return t.family }

func (t Token) IssuedAt() time.Time { return t.issuedAt }

func (t Token) ExpiresAt() time.Time { return t.expiresAt }

// Attrs returns the session attributes decoded from "att".
func (t Token) Attrs() core.SessionAttrs { return t.attrs }

// Claims returns the compact application claims carried in "apc".
func (t Token) Claims() core.SealedClaims { return t.claims }

// NewCodec returns ErrInvalidConfig for an origin that is not an http(s) origin, an empty or
// overlong claims fingerprint, or a non-positive RecheckEvery.
func NewCodec(cfg CodecConfig) (*Codec, error) {
	if err := checkOrigin(cfg.PublicOrigin); err != nil {
		return nil, err
	}
	if cfg.ClaimsFingerprint == "" || len(cfg.ClaimsFingerprint) > maxFingerprint {
		return nil, errors.Join(ErrInvalidConfig, errors.New("jwt: claims fingerprint must be 1 to 128 bytes"))
	}
	if cfg.RecheckEvery < time.Second {
		return nil, errors.Join(ErrInvalidConfig, errors.New("jwt: RecheckEvery must be at least one second"))
	}
	m, err := signing.NewMinter(signingOwner{})
	if err != nil {
		return nil, errors.Join(ErrInvalidConfig, err)
	}
	return &Codec{minter: m, origin: cfg.PublicOrigin, fingerprint: cfg.ClaimsFingerprint, recheck: cfg.RecheckEvery, clk: cfg.Clock}, nil
}

func checkOrigin(origin string) error {
	if strings.Count(origin, tenantMarker) > 1 {
		return errors.Join(ErrInvalidConfig, errors.New("jwt: more than one {tenant} label"))
	}
	u, err := url.Parse(strings.Replace(origin, tenantMarker, "tenant", 1))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return errors.Join(ErrInvalidConfig, errors.New("jwt: public origin is not an http(s) origin"))
	}
	if strings.Contains(origin, tenantMarker) && !strings.HasPrefix(u.Host, "tenant.") {
		return errors.Join(ErrInvalidConfig, errors.New("jwt: {tenant} must be the first host label"))
	}
	return nil
}

// Issuer returns the "iss" of t's tokens: the public origin with t as its {tenant} label. A
// tenant-templated origin returns ErrInvalidToken for the single tenant or a tenant that is not a
// lower-case DNS label.
func (c *Codec) Issuer(t principal.TenantID) (string, error) {
	if !strings.Contains(c.origin, tenantMarker) {
		return c.origin, nil
	}
	if !dnsLabel(t.String()) {
		return "", errors.Join(ErrInvalidToken, errors.New("jwt: tenant is not a host label"))
	}
	return strings.Replace(c.origin, tenantMarker, t.String(), 1), nil
}

func dnsLabel(s string) bool {
	if s == "" || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

type mint struct {
	audience string
	family   uuid.UUID
	issuedAt time.Time
	lifetime time.Duration
	attrs    core.SessionAttrs
	claims   core.SealedClaims
}

func (c *Codec) encode(s signing.Signer, m mint) (string, Token, error) {
	if m.attrs.IsZero() || m.family == uuid.Nil || m.lifetime < time.Second || m.lifetime > c.recheck {
		return "", Token{}, errors.Join(core.ErrInvalidArgument, errors.New("jwt: token to mint"))
	}
	sub := m.attrs.Subject()
	iss, err := c.Issuer(sub.Tenant)
	if err != nil {
		return "", Token{}, err
	}
	aud := m.audience
	if aud == "" {
		aud = iss
	}
	sealed, err := core.Seal(m.attrs)
	if err != nil {
		return "", Token{}, err
	}
	claims, err := session.CompactClaims(m.claims.Bytes())
	if err != nil {
		return "", Token{}, err
	}
	iat := m.issuedAt.Unix()
	exp := iat + int64(m.lifetime/time.Second)
	cs := claimSet{
		Iss: iss, Aud: aud, Sub: sub.User.String(), Tid: sub.Tenant.String(), Sid: m.family.String(),
		Iat: iat, Exp: exp, Typ: TokenType, Egv: Version, Egc: c.fingerprint,
		Att: b64.EncodeToString(sealed.Bytes()), Apc: claims.Bytes(),
		AMR: m.attrs.AMR(), AuthTime: m.attrs.PrimaryAt().Unix(),
	}
	hb, err := marshal(header{Alg: s.Algorithm(), Kid: s.KeyID(), Typ: TokenType})
	if err != nil {
		return "", Token{}, err
	}
	pb, err := marshal(cs)
	if err != nil {
		return "", Token{}, err
	}
	input := b64.EncodeToString(hb) + "." + b64.EncodeToString(pb)
	sig, err := c.minter.Sign(s, input)
	if err != nil {
		return "", Token{}, err
	}
	return input + "." + b64.EncodeToString(sig), Token{
		issuer: iss, audience: aud, family: m.family,
		issuedAt: time.Unix(iat, 0).UTC(), expiresAt: time.Unix(exp, 0).UTC(),
		attrs: m.attrs, claims: claims,
	}, nil
}

func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func strictDecode(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

// VerifySession verifies a session access token: its "aud" must be its issuer. It returns
// ErrExpired once the token is at or past its "exp", ErrInvalidToken for any other defect, and an
// error joined with httpx.ErrUnavailable when the key source cannot answer.
func (c *Codec) VerifySession(ctx context.Context, raw string, keys KeySource) (Token, error) {
	tok, expired, err := c.verify(ctx, raw, keys, "")
	if err != nil {
		return Token{}, err
	}
	if expired {
		return Token{}, ErrExpired
	}
	return tok, nil
}

// VerifyResource verifies a resource token minted for audience, which must not be empty; session
// tokens are refused. Errors are those of VerifySession.
func (c *Codec) VerifyResource(ctx context.Context, raw string, keys KeySource, audience string) (Token, error) {
	if audience == "" {
		return Token{}, errors.Join(ErrInvalidToken, errors.New("jwt: a resource audience is required"))
	}
	tok, expired, err := c.verify(ctx, raw, keys, audience)
	if err != nil {
		return Token{}, err
	}
	if expired {
		return Token{}, ErrExpired
	}
	return tok, nil
}

func invalid(reason string) error {
	return errors.Join(ErrInvalidToken, errors.New("jwt: "+reason))
}

func (c *Codec) verify(ctx context.Context, raw string, keys KeySource, audience string) (Token, bool, error) {
	if raw == "" || len(raw) > MaxTokenLen {
		return Token{}, false, invalid("token length")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Token{}, false, invalid("not a compact JWS")
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return Token{}, false, invalid("header encoding")
	}
	var h header
	if err := strictDecode(hb, &h); err != nil || h.Typ != TokenType || h.Alg == "" || h.Kid == "" {
		return Token{}, false, invalid("header")
	}
	pb, err := b64.DecodeString(parts[1])
	if err != nil {
		return Token{}, false, invalid("payload encoding")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return Token{}, false, invalid("signature encoding")
	}
	var cs claimSet
	if err := strictDecode(pb, &cs); err != nil {
		return Token{}, false, invalid("claim set")
	}
	tenant, err := parseTenant(cs.Tid)
	if err != nil {
		return Token{}, false, invalid("tenant")
	}
	tok, expired, err := c.check(cs, tenant, audience)
	if err != nil {
		return Token{}, false, err
	}
	v, err := keys.Verifier(ctx, tenant, h.Kid)
	if err != nil {
		if errors.Is(err, revoke.ErrUnavailable) {
			return Token{}, false, errors.Join(httpx.ErrUnavailable, err)
		}
		return Token{}, false, errors.Join(ErrInvalidToken, err)
	}
	if err := v.Verify(signing.Signed{Algorithm: h.Alg, KeyID: h.Kid, Input: parts[0] + "." + parts[1], Signature: sig}); err != nil {
		return Token{}, false, errors.Join(ErrInvalidToken, err)
	}
	return tok, expired, nil
}

func parseTenant(s string) (principal.TenantID, error) {
	if s == "" {
		return principal.TenantID{}, nil
	}
	return principal.ParseTenantID(s)
}

func (c *Codec) check(cs claimSet, tenant principal.TenantID, audience string) (Token, bool, error) {
	if cs.Typ != TokenType || cs.Egv != Version {
		return Token{}, false, invalid("token format version")
	}
	if cs.Egc != c.fingerprint {
		return Token{}, false, invalid("claims fingerprint")
	}
	iss, err := c.Issuer(tenant)
	if err != nil || cs.Iss != iss {
		return Token{}, false, invalid("issuer")
	}
	want := audience
	if want == "" {
		want = iss
	}
	if cs.Aud != want || (audience != "" && cs.Aud == iss) {
		return Token{}, false, invalid("audience")
	}
	now := c.clk.Now()
	if cs.Iat <= 0 || cs.Exp <= cs.Iat || cs.Exp > maxUnixSeconds || cs.Exp-cs.Iat > int64(c.recheck/time.Second) {
		return Token{}, false, invalid("lifetime")
	}
	if time.Unix(cs.Iat, 0).After(now.Add(MaxIssuedAtSkew)) {
		return Token{}, false, invalid("issued in the future")
	}
	family, err := uuid.Parse(cs.Sid)
	if err != nil || family == uuid.Nil || cs.Sid != family.String() {
		return Token{}, false, invalid("sid")
	}
	user, err := uuid.Parse(cs.Sub)
	if err != nil || user == uuid.Nil || cs.Sub != user.String() {
		return Token{}, false, invalid("sub")
	}
	sealed, err := b64.DecodeString(cs.Att)
	if err != nil {
		return Token{}, false, invalid("att encoding")
	}
	attrs, err := core.Unseal(core.SealedFromBytes(sealed))
	if err != nil {
		return Token{}, false, errors.Join(ErrInvalidToken, err)
	}
	if attrs.Subject() != (principal.Subject{Tenant: tenant, User: user}) {
		return Token{}, false, invalid("sub and tid disagree with att")
	}
	claims, err := session.CompactClaims(cs.Apc)
	if err != nil || !bytes.Equal(claims.Bytes(), cs.Apc) {
		return Token{}, false, invalid("apc")
	}
	exp := time.Unix(cs.Exp, 0).UTC()
	return Token{
		issuer: cs.Iss, audience: cs.Aud, family: family,
		issuedAt: time.Unix(cs.Iat, 0).UTC(), expiresAt: exp,
		attrs: attrs, claims: claims,
	}, !now.Before(exp), nil
}
