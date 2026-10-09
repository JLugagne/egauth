// Package webauthntest is a virtual WebAuthn platform authenticator and the client that drives it
// from one origin, for tests (G24, X-13). Unlike a double that always answers yes, it honours the
// options it is given the way WebAuthn Level 3 browsers do: residentKey and requireResidentKey
// decide whether the credential is discoverable, credProps reports that decision, excluded
// credentials and foreign relying party ids fail create(), userVerification decides the UV flag,
// and a discoverable get() fails when no resident credential exists for the RP id. Knobs on
// Authenticator model the clients and authenticators a relying party must survive.
//
// Options are the JSON that navigator.credentials.create() and get() receive, with or without the
// {"publicKey": ...} wrapper; responses are the PublicKeyCredential JSON a client posts back.
// Only ES256 with "none" attestation is produced. The ceremony methods are safe for concurrent use;
// the knobs are not, so set them before the first ceremony.
package webauthntest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// The errors of Create and Get, named after the DOMException a browser raises.
var (
	// ErrNotAllowed is returned when no credential matches a get(), or when create() cannot store
	// the resident key the options require.
	ErrNotAllowed = errors.New("webauthntest: NotAllowedError")
	// ErrInvalidState is returned when create() finds an excluded credential on the authenticator.
	ErrInvalidState = errors.New("webauthntest: InvalidStateError")
	// ErrSecurity is returned when the RP id is neither the origin's host nor one of its parents.
	ErrSecurity = errors.New("webauthntest: SecurityError")
	// ErrNotSupported is returned when pubKeyCredParams does not offer ES256.
	ErrNotSupported = errors.New("webauthntest: NotSupportedError")
	// ErrInvalidOptions is returned for options that are not WebAuthn options JSON.
	ErrInvalidOptions = errors.New("webauthntest: malformed options")
)

const (
	residentRequired    = "required"
	residentPreferred   = "preferred"
	residentDiscouraged = "discouraged"
	uvDiscouraged       = "discouraged"
	algES256            = -7
	residentIDLen       = 16
	serverSideIDLen     = 48
	flagUP              = 0x01
	flagUV              = 0x04
	flagBE              = 0x08
	flagBS              = 0x10
	flagAT              = 0x40
)

var b64 = base64.RawURLEncoding

// Credential describes one credential held by an Authenticator.
type Credential struct {
	ID         []byte
	RPID       string
	UserHandle []byte
	// Resident reports a client-side discoverable credential.
	Resident  bool
	SignCount uint32
}

type credential struct {
	Credential
	key *ecdsa.PrivateKey
}

// Authenticator is one virtual platform authenticator behind a client running at one origin. Its
// zero knobs describe an honest, capable passkey provider. Set the knobs before the first ceremony.
type Authenticator struct {
	// ResidentKeyUnsupported makes the authenticator able to create server-side credentials only:
	// create() with a required resident key then fails with ErrNotAllowed, as WebAuthn L3 §5.1.3
	// mandates, and a preferred one yields a server-side credential.
	ResidentKeyUnsupported bool
	// ClientResidentKey, when set, is written by the client over the options' residentKey (and
	// requireResidentKey made to match) before the authenticator reads them: a client that rewrites
	// the relying party's options (C-16).
	ClientResidentKey string
	// ClientUserVerification, when set, is written by the client over the options'
	// userVerification; "discouraged" yields assertions and attestations without the UV flag.
	ClientUserVerification string
	// OmitCredProps drops the credProps client extension output even when it was requested.
	OmitCredProps bool
	// Counterless keeps every signature counter at zero, like a synced passkey provider.
	Counterless bool
	// BackupEligible and BackedUp set the BE and BS flags of every authenticator data.
	BackupEligible bool
	BackedUp       bool

	origin string
	host   string
	mu     sync.Mutex
	creds  []*credential
}

// New returns an empty authenticator whose client runs at origin, an absolute http or https origin.
// An origin without a host makes every ceremony fail with ErrSecurity.
func New(origin string) *Authenticator {
	host := ""
	if u, err := url.Parse(origin); err == nil {
		host = strings.ToLower(u.Hostname())
	}
	return &Authenticator{origin: origin, host: host}
}

// Clone returns an independent copy holding the same private keys and counters: using both makes
// one of them present a counter that has already been seen, the clone signal of WebAuthn §6.1.1.
func (a *Authenticator) Clone() *Authenticator {
	a.mu.Lock()
	defer a.mu.Unlock()
	c := &Authenticator{
		ResidentKeyUnsupported: a.ResidentKeyUnsupported,
		ClientResidentKey:      a.ClientResidentKey,
		ClientUserVerification: a.ClientUserVerification,
		OmitCredProps:          a.OmitCredProps,
		Counterless:            a.Counterless,
		BackupEligible:         a.BackupEligible,
		BackedUp:               a.BackedUp,
		origin:                 a.origin,
		host:                   a.host,
	}
	for _, cr := range a.creds {
		cp := *cr
		cp.ID = slices.Clone(cr.ID)
		cp.UserHandle = slices.Clone(cr.UserHandle)
		c.creds = append(c.creds, &cp)
	}
	return c
}

// Credentials returns a copy of the credentials held, oldest first.
func (a *Authenticator) Credentials() []Credential {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Credential, 0, len(a.creds))
	for _, c := range a.creds {
		cp := c.Credential
		cp.ID = slices.Clone(c.ID)
		cp.UserHandle = slices.Clone(c.UserHandle)
		out = append(out, cp)
	}
	return out
}

// Register is Create that fails t instead of returning the error.
func (a *Authenticator) Register(t testing.TB, creationOptionsJSON []byte) []byte {
	t.Helper()
	out, err := a.Create(creationOptionsJSON)
	if err != nil {
		t.Fatalf("webauthntest: create(): %v", err)
		return nil
	}
	return out
}

// Login is Get that fails t instead of returning the error.
func (a *Authenticator) Login(t testing.TB, requestOptionsJSON []byte) []byte {
	t.Helper()
	out, err := a.Get(requestOptionsJSON)
	if err != nil {
		t.Fatalf("webauthntest: get(): %v", err)
		return nil
	}
	return out
}

// DiscoverableLogin answers a usernameless get(): it fails t when the options carry an allow list
// or when no resident credential exists for their RP id.
func (a *Authenticator) DiscoverableLogin(t testing.TB, requestOptionsJSON []byte) []byte {
	t.Helper()
	opts, err := parseRequest(requestOptionsJSON)
	if err != nil {
		t.Fatalf("webauthntest: discoverable get(): %v", err)
		return nil
	}
	if len(opts.AllowCredentials) > 0 {
		t.Fatalf("webauthntest: discoverable get(): options carry an allow list")
		return nil
	}
	return a.Login(t, requestOptionsJSON)
}

type descriptor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type creationOptions struct {
	RP struct {
		ID string `json:"id"`
	} `json:"rp"`
	User struct {
		ID string `json:"id"`
	} `json:"user"`
	Challenge              string       `json:"challenge"`
	PubKeyCredParams       []credParam  `json:"pubKeyCredParams"`
	ExcludeCredentials     []descriptor `json:"excludeCredentials"`
	AuthenticatorSelection struct {
		ResidentKey        string `json:"residentKey"`
		RequireResidentKey *bool  `json:"requireResidentKey"`
		UserVerification   string `json:"userVerification"`
	} `json:"authenticatorSelection"`
	Extensions map[string]json.RawMessage `json:"extensions"`
}

type credParam struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

type requestOptions struct {
	Challenge        string       `json:"challenge"`
	RPID             string       `json:"rpId"`
	AllowCredentials []descriptor `json:"allowCredentials"`
	UserVerification string       `json:"userVerification"`
}

func unwrap(raw []byte) ([]byte, error) {
	var wrapper struct {
		PublicKey json.RawMessage `json:"publicKey"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return nil, errors.Join(ErrInvalidOptions, err)
	}
	if len(wrapper.PublicKey) > 0 {
		return wrapper.PublicKey, nil
	}
	return raw, nil
}

func decode64(s string) ([]byte, error) {
	if b, err := b64.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

func parseCreation(raw []byte) (creationOptions, []byte, error) {
	var o creationOptions
	body, err := unwrap(raw)
	if err != nil {
		return o, nil, err
	}
	if err := json.Unmarshal(body, &o); err != nil {
		return o, nil, errors.Join(ErrInvalidOptions, err)
	}
	if _, err := decode64(o.Challenge); err != nil || o.Challenge == "" {
		return o, nil, errors.Join(ErrInvalidOptions, errors.New("challenge"))
	}
	handle, err := decode64(o.User.ID)
	if err != nil || len(handle) == 0 || len(handle) > 64 {
		return o, nil, errors.Join(ErrInvalidOptions, errors.New("user.id"))
	}
	return o, handle, nil
}

func parseRequest(raw []byte) (requestOptions, error) {
	var o requestOptions
	body, err := unwrap(raw)
	if err != nil {
		return o, err
	}
	if err := json.Unmarshal(body, &o); err != nil {
		return o, errors.Join(ErrInvalidOptions, err)
	}
	if _, err := decode64(o.Challenge); err != nil || o.Challenge == "" {
		return o, errors.Join(ErrInvalidOptions, errors.New("challenge"))
	}
	return o, nil
}

func (a *Authenticator) relyingParty(id string) (string, error) {
	if id == "" {
		id = a.host
	}
	id = strings.ToLower(id)
	if a.host == "" || id == "" || (a.host != id && !strings.HasSuffix(a.host, "."+id)) {
		return "", errors.Join(ErrSecurity, errors.New("rp id "+id+" is not a registrable suffix of "+a.origin))
	}
	return id, nil
}

func (a *Authenticator) residentKey(o creationOptions) string {
	rk := o.AuthenticatorSelection.ResidentKey
	if a.ClientResidentKey != "" {
		rk = a.ClientResidentKey
	}
	switch rk {
	case residentRequired, residentPreferred, residentDiscouraged:
		return rk
	}
	if r := o.AuthenticatorSelection.RequireResidentKey; r != nil && *r {
		return residentRequired
	}
	return residentDiscouraged
}

func (a *Authenticator) verifies(requested string) bool {
	if a.ClientUserVerification != "" {
		requested = a.ClientUserVerification
	}
	return requested != uvDiscouraged
}

func offersES256(ps []credParam) bool {
	if len(ps) == 0 {
		return true
	}
	return slices.ContainsFunc(ps, func(p credParam) bool { return p.Type == "public-key" && p.Alg == algES256 })
}

// Create runs navigator.credentials.create() with creationOptionsJSON and returns the registration
// response JSON. The credential is resident when the effective residentKey is required, or
// preferred on a capable authenticator; credProps, when requested and not omitted, reports exactly
// that. It returns ErrInvalidOptions, ErrSecurity, ErrNotSupported, ErrInvalidState or ErrNotAllowed
// and stores nothing then.
func (a *Authenticator) Create(creationOptionsJSON []byte) ([]byte, error) {
	o, handle, err := parseCreation(creationOptionsJSON)
	if err != nil {
		return nil, err
	}
	rp, err := a.relyingParty(o.RP.ID)
	if err != nil {
		return nil, err
	}
	if !offersES256(o.PubKeyCredParams) {
		return nil, ErrNotSupported
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, d := range o.ExcludeCredentials {
		id, err := decode64(d.ID)
		if err != nil {
			return nil, errors.Join(ErrInvalidOptions, errors.New("excludeCredentials"))
		}
		if a.holds(rp, id) {
			return nil, ErrInvalidState
		}
	}
	resident := false
	switch a.residentKey(o) {
	case residentRequired:
		if a.ResidentKeyUnsupported {
			return nil, errors.Join(ErrNotAllowed, errors.New("a resident key is required and the authenticator cannot store one"))
		}
		resident = true
	case residentPreferred:
		resident = !a.ResidentKeyUnsupported
	}
	c, err := newCredential(rp, handle, resident)
	if err != nil {
		return nil, err
	}
	uv := a.verifies(o.AuthenticatorSelection.UserVerification)
	authData, err := a.authData(c, flagUP|flagAT|a.uvFlag(uv), true)
	if err != nil {
		return nil, err
	}
	att, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": authData})
	if err != nil {
		return nil, err
	}
	cd, err := a.clientData("webauthn.create", o.Challenge)
	if err != nil {
		return nil, err
	}
	ext := map[string]any{}
	if wantsCredProps(o.Extensions) && !a.OmitCredProps {
		ext["credProps"] = map[string]bool{"rk": resident}
	}
	if resident {
		a.creds = slices.DeleteFunc(a.creds, func(e *credential) bool {
			return e.Resident && e.RPID == rp && bytes.Equal(e.UserHandle, handle)
		})
	}
	a.creds = append(a.creds, c)
	return json.Marshal(map[string]any{
		"id":                      b64.EncodeToString(c.ID),
		"rawId":                   b64.EncodeToString(c.ID),
		"type":                    "public-key",
		"authenticatorAttachment": "platform",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(cd),
			"attestationObject": b64.EncodeToString(att),
			"transports":        []string{"hybrid", "internal"},
		},
		"clientExtensionResults": ext,
	})
}

func wantsCredProps(ext map[string]json.RawMessage) bool {
	var on bool
	return json.Unmarshal(ext["credProps"], &on) == nil && on
}

func newCredential(rp string, handle []byte, resident bool) (*credential, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	n := serverSideIDLen
	if resident {
		n = residentIDLen
	}
	id := make([]byte, n)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	return &credential{Credential: Credential{ID: id, RPID: rp, UserHandle: slices.Clone(handle), Resident: resident}, key: key}, nil
}

func (a *Authenticator) holds(rp string, id []byte) bool {
	return slices.ContainsFunc(a.creds, func(c *credential) bool { return c.RPID == rp && bytes.Equal(c.ID, id) })
}

func (a *Authenticator) uvFlag(uv bool) byte {
	if uv {
		return flagUV
	}
	return 0
}

func (a *Authenticator) authData(c *credential, flags byte, attested bool) ([]byte, error) {
	if a.BackupEligible {
		flags |= flagBE
	}
	if a.BackedUp {
		flags |= flagBS
	}
	rpHash := sha256.Sum256([]byte(c.RPID))
	var buf bytes.Buffer
	buf.Write(rpHash[:])
	buf.WriteByte(flags)
	buf.Write(binary.BigEndian.AppendUint32(nil, c.SignCount))
	if !attested {
		return buf.Bytes(), nil
	}
	buf.Write(make([]byte, 16))
	buf.Write(binary.BigEndian.AppendUint16(nil, uint16(len(c.ID))))
	buf.Write(c.ID)
	key, err := coseKey(c.key)
	if err != nil {
		return nil, err
	}
	buf.Write(key)
	return buf.Bytes(), nil
}

func coseKey(k *ecdsa.PrivateKey) ([]byte, error) {
	raw, err := k.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(map[int]any{1: 2, 3: algES256, -1: 1, -2: raw[1:33], -3: raw[33:65]})
}

type collectedClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

func (a *Authenticator) clientData(typ, challenge string) ([]byte, error) {
	return json.Marshal(collectedClientData{Type: typ, Challenge: challenge, Origin: a.origin})
}

// Get runs navigator.credentials.get() with requestOptionsJSON and returns the assertion response
// JSON. An empty allow list is a discoverable request answered by the newest resident credential of
// the RP id, with its user handle; otherwise the newest held credential of the allow list answers,
// with a user handle only when it is resident. The counter advances unless Counterless. It returns
// ErrInvalidOptions, ErrSecurity or ErrNotAllowed.
func (a *Authenticator) Get(requestOptionsJSON []byte) ([]byte, error) {
	o, err := parseRequest(requestOptionsJSON)
	if err != nil {
		return nil, err
	}
	rp, err := a.relyingParty(o.RPID)
	if err != nil {
		return nil, err
	}
	allowed := make([][]byte, 0, len(o.AllowCredentials))
	for _, d := range o.AllowCredentials {
		id, err := decode64(d.ID)
		if err != nil {
			return nil, errors.Join(ErrInvalidOptions, errors.New("allowCredentials"))
		}
		allowed = append(allowed, id)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.pick(rp, allowed)
	if c == nil {
		return nil, errors.Join(ErrNotAllowed, errors.New("no matching credential for "+rp))
	}
	if !a.Counterless {
		c.SignCount++
	}
	authData, err := a.authData(c, flagUP|a.uvFlag(a.verifies(o.UserVerification)), false)
	if err != nil {
		return nil, err
	}
	cd, err := a.clientData("webauthn.get", o.Challenge)
	if err != nil {
		return nil, err
	}
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(slices.Clone(authData), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, c.key, digest[:])
	if err != nil {
		return nil, err
	}
	resp := map[string]any{
		"clientDataJSON":    b64.EncodeToString(cd),
		"authenticatorData": b64.EncodeToString(authData),
		"signature":         b64.EncodeToString(sig),
	}
	if c.Resident {
		resp["userHandle"] = b64.EncodeToString(c.UserHandle)
	}
	return json.Marshal(map[string]any{
		"id":                      b64.EncodeToString(c.ID),
		"rawId":                   b64.EncodeToString(c.ID),
		"type":                    "public-key",
		"authenticatorAttachment": "platform",
		"response":                resp,
		"clientExtensionResults":  map[string]any{},
	})
}

func (a *Authenticator) pick(rp string, allowed [][]byte) *credential {
	for i := len(a.creds) - 1; i >= 0; i-- {
		c := a.creds[i]
		if c.RPID != rp {
			continue
		}
		if len(allowed) == 0 && c.Resident {
			return c
		}
		if slices.ContainsFunc(allowed, func(id []byte) bool { return bytes.Equal(id, c.ID) }) {
			return c
		}
	}
	return nil
}
