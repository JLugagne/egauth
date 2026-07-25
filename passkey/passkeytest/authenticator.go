// Package passkeytest provides a software WebAuthn authenticator for integration
// testing passkey flows without network calls or a real hardware authenticator.
//
// The [SoftAuthenticator] implements the ES256 (P-256) / "none"-attestation subset
// of the WebAuthn spec — exactly what go-webauthn accepts for registration and login
// ceremonies in test environments.  Consumers integration-testing their passkey
// wiring use it to drive [passkey.Service] end-to-end without re-implementing the
// ~200 lines of WebAuthn wire-format assembly.
//
// Usage:
//
//	auth := passkeytest.NewSoftAuthenticator(t, "localhost", "http://localhost")
//	// registration
//	creation, session, _ := svc.BeginRegistration(ctx, tenant, userID, "alice", "Alice")
//	challenge := base64.RawURLEncoding.EncodeToString(session.Challenge)
//	svc.FinishRegistration(ctx, tenant, userID, "alice", "Alice", *session, auth.RegistrationRequest(t, challenge))
//	// login
//	assertion, session2, _ := svc.BeginLogin(ctx, tenant, userID)
//	challenge2 := base64.RawURLEncoding.EncodeToString(session2.Challenge)
//	svc.FinishLogin(ctx, tenant, userID, *session2, auth.LoginRequest(t, challenge2, userID[:]))
package passkeytest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// WebAuthn authenticator-data flag bits used when constructing ceremonies.
const (
	FlagUP = byte(0x01) // user present
	FlagUV = byte(0x04) // user verified
	FlagAT = byte(0x40) // attested credential data included (registration only)
	FlagBE = byte(0x08) // backup eligible
	FlagBS = byte(0x10) // backup state (backed up)
)

// SoftAuthenticator is a minimal software WebAuthn authenticator for tests.
// It produces attestation (registration) and assertion (login) responses that
// go-webauthn verifies end-to-end, using "none" attestation and ES256 / P-256 keys.
//
// Create one with [NewSoftAuthenticator].  A single SoftAuthenticator instance
// maintains its own sign counter, so successive [SoftAuthenticator.LoginRequest]
// calls properly increment the counter as a real authenticator does.
type SoftAuthenticator struct {
	// RPID is the relying-party ID (e.g. "localhost").
	RPID string
	// Origin is the origin (e.g. "http://localhost").
	Origin string
	// CredentialID is the raw credential identifier assigned at creation.
	CredentialID []byte

	key        *ecdsa.PrivateKey
	aaguid     []byte
	signCount  uint32
	transports []string
}

// NewSoftAuthenticator creates a SoftAuthenticator bound to rpID and origin.
// It generates a fresh P-256 key pair and a random credential ID.
func NewSoftAuthenticator(t testing.TB, rpID, origin string) *SoftAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	credID := make([]byte, 16)
	_, err = rand.Read(credID)
	require.NoError(t, err)
	return &SoftAuthenticator{
		RPID:         rpID,
		Origin:       origin,
		CredentialID: credID,
		key:          key,
		aaguid:       make([]byte, 16),
		transports:   []string{"internal", "hybrid"},
	}
}

// RegistrationRequest produces the HTTP request body for FinishRegistration.
// challenge is the base64url-encoded session challenge from BeginRegistration.
func (a *SoftAuthenticator) RegistrationRequest(t testing.TB, challenge string) *http.Request {
	t.Helper()
	return a.RegistrationRequestWithFlags(t, challenge, FlagUP|FlagUV|FlagAT)
}

// RegistrationRequestWithFlags is like [SoftAuthenticator.RegistrationRequest] but lets
// the caller control the authenticator-data flag bits (e.g. add FlagBE/FlagBS to
// assert backup eligibility/state).
func (a *SoftAuthenticator) RegistrationRequestWithFlags(t testing.TB, challenge string, flags byte) *http.Request {
	t.Helper()
	authData := a.authData(t, flags, true)
	attObj := map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	}
	attCBOR, err := cbor.Marshal(attObj)
	require.NoError(t, err)

	body := map[string]any{
		"id":    b64(a.CredentialID),
		"rawId": b64(a.CredentialID),
		"type":  "public-key",
		"response": map[string]any{
			"attestationObject": b64(attCBOR),
			"clientDataJSON":    b64(clientDataJSON(t, "webauthn.create", challenge, a.Origin)),
			"transports":        a.transports,
		},
		"clientExtensionResults": map[string]any{},
	}
	return jsonPost(t, body)
}

// LoginRequest produces the HTTP request body for FinishLogin or FinishDiscoverableLogin.
// challenge is the base64url-encoded session challenge from BeginLogin.
// userHandle is the user handle included in the assertion (pass userID[:] for a UUID).
// The authenticator's internal sign counter is incremented, matching real-authenticator behavior.
func (a *SoftAuthenticator) LoginRequest(t testing.TB, challenge string, userHandle []byte) *http.Request {
	t.Helper()
	a.signCount++
	return a.assertion(t, challenge, userHandle, a.signCount)
}

// LoginRequestAtCount signs an assertion at a fixed signature count without bumping
// the internal counter.  Use this to forge a cloned or replayed assertion (where the
// count is lower than the stored value) in clone-detection tests.
func (a *SoftAuthenticator) LoginRequestAtCount(t testing.TB, challenge string, userHandle []byte, count uint32) *http.Request {
	t.Helper()
	prev := a.signCount
	a.signCount = count
	req := a.assertion(t, challenge, userHandle, count)
	a.signCount = prev
	return req
}

// LoginRequestWithFlags is like [SoftAuthenticator.LoginRequest] but lets the caller
// control the authenticator-data flag bits (e.g. omit FlagUV to forge an assertion
// where the user was not verified — for user-verification tests).
func (a *SoftAuthenticator) LoginRequestWithFlags(t testing.TB, challenge string, userHandle []byte, count uint32, flags byte) *http.Request {
	t.Helper()
	a.signCount = count
	return a.assertionWithFlags(t, challenge, userHandle, count, flags)
}

// UserHandleOf is a convenience helper that returns the user handle bytes from a UUID
// (the format egauth uses internally for WebAuthn user handles).
func UserHandleOf(id uuid.UUID) []byte {
	b := id
	return b[:]
}

// --- internal helpers ---

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// coseKey encodes the credential's public key as a COSE_Key (ES256 / P-256).
func (a *SoftAuthenticator) coseKey(t testing.TB) []byte {
	t.Helper()
	raw, err := a.key.PublicKey.Bytes() // 0x04 || X || Y (each 32 bytes)
	require.NoError(t, err)
	x, y := raw[1:33], raw[33:65]
	key := map[int]any{
		1:  2,  // kty: EC2
		3:  -7, // alg: ES256
		-1: 1,  // crv: P-256
		-2: x,
		-3: y,
	}
	enc, err := cbor.Marshal(key)
	require.NoError(t, err)
	return enc
}

// authData builds authenticatorData: rpIDHash || flags || signCount [|| attestedCredentialData].
func (a *SoftAuthenticator) authData(t testing.TB, flags byte, withCred bool) []byte {
	t.Helper()
	rpHash := sha256.Sum256([]byte(a.RPID))
	var buf bytes.Buffer
	buf.Write(rpHash[:])
	buf.WriteByte(flags)
	_ = binary.Write(&buf, binary.BigEndian, a.signCount)
	if withCred {
		buf.Write(a.aaguid) // 16 bytes
		credLen := make([]byte, 2)
		binary.BigEndian.PutUint16(credLen, uint16(len(a.CredentialID))) //#nosec G115 -- test-only soft authenticator; CredentialID is generated in-process, never attacker-sized
		buf.Write(credLen)
		buf.Write(a.CredentialID)
		buf.Write(a.coseKey(t))
	}
	return buf.Bytes()
}

func clientDataJSON(t testing.TB, typ, challenge, origin string) []byte {
	t.Helper()
	cd := map[string]any{
		"type":        typ,
		"challenge":   challenge,
		"origin":      origin,
		"crossOrigin": false,
	}
	b, err := json.Marshal(cd)
	require.NoError(t, err)
	return b
}

func (a *SoftAuthenticator) assertion(t testing.TB, challenge string, userHandle []byte, count uint32) *http.Request {
	t.Helper()
	return a.assertionWithFlags(t, challenge, userHandle, count, FlagUP|FlagUV)
}

func (a *SoftAuthenticator) assertionWithFlags(t testing.TB, challenge string, userHandle []byte, count uint32, flags byte) *http.Request {
	t.Helper()
	a.signCount = count
	authData := a.authData(t, flags, false)
	cd := clientDataJSON(t, "webauthn.get", challenge, a.Origin)
	cdHash := sha256.Sum256(cd)
	signed := append(append([]byte{}, authData...), cdHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	require.NoError(t, err)

	resp := map[string]any{
		"authenticatorData": b64(authData),
		"clientDataJSON":    b64(cd),
		"signature":         b64(sig),
	}
	if userHandle != nil {
		resp["userHandle"] = b64(userHandle)
	}
	body := map[string]any{
		"id":                     b64(a.CredentialID),
		"rawId":                  b64(a.CredentialID),
		"type":                   "public-key",
		"response":               resp,
		"clientExtensionResults": map[string]any{},
	}
	return jsonPost(t, body)
}

func jsonPost(t testing.TB, body map[string]any) *http.Request {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	return req
}
