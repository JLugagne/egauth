package passkey_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// softAuthenticator is a minimal software WebAuthn authenticator for tests. It produces the
// attestation (registration) and assertion (login) responses go-webauthn verifies, using a
// "none" attestation and an ES256 (P-256) credential key — enough to drive the full Finish
// ceremonies end-to-end (signature verification, clone detection, sign-count persistence).
type softAuthenticator struct {
	rpID      string
	origin    string
	key       *ecdsa.PrivateKey
	credID    []byte
	aaguid    []byte
	signCount uint32
}

// WebAuthn authenticator-data flag bits.
const (
	flagUP = 0x01 // user present
	flagUV = 0x04 // user verified
	flagAT = 0x40 // attested credential data included
)

func newSoftAuthenticator(t *testing.T, rpID, origin string) *softAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	credID := make([]byte, 16)
	_, err = rand.Read(credID)
	require.NoError(t, err)
	return &softAuthenticator{rpID: rpID, origin: origin, key: key, credID: credID, aaguid: make([]byte, 16)}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// coseKey encodes the credential's public key as a COSE_Key (ES256 / P-256).
func (a *softAuthenticator) coseKey(t *testing.T) []byte {
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
func (a *softAuthenticator) authData(t *testing.T, flags byte, withCred bool) []byte {
	t.Helper()
	rpHash := sha256.Sum256([]byte(a.rpID))
	var buf bytes.Buffer
	buf.Write(rpHash[:])
	buf.WriteByte(flags)
	_ = binary.Write(&buf, binary.BigEndian, a.signCount)
	if withCred {
		buf.Write(a.aaguid) // 16 bytes
		credLen := make([]byte, 2)
		binary.BigEndian.PutUint16(credLen, uint16(len(a.credID)))
		buf.Write(credLen)
		buf.Write(a.credID)
		buf.Write(a.coseKey(t))
	}
	return buf.Bytes()
}

func clientDataJSON(t *testing.T, typ, challenge, origin string) []byte {
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

// registrationRequest produces the POST request body FinishRegistration parses, for the given
// ceremony challenge (the base64url SessionData.Challenge).
func (a *softAuthenticator) registrationRequest(t *testing.T, challenge string) *http.Request {
	t.Helper()
	authData := a.authData(t, flagUP|flagUV|flagAT, true)
	attObj := map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	}
	attCBOR, err := cbor.Marshal(attObj)
	require.NoError(t, err)

	body := map[string]any{
		"id":    b64(a.credID),
		"rawId": b64(a.credID),
		"type":  "public-key",
		"response": map[string]any{
			"attestationObject": b64(attCBOR),
			"clientDataJSON":    b64(clientDataJSON(t, "webauthn.create", challenge, a.origin)),
		},
		"clientExtensionResults": map[string]any{},
	}
	return jsonPost(t, body)
}

// loginRequest produces the POST request body FinishLogin / FinishDiscoverableLogin parses. It
// increments the authenticator's signature counter (as a real authenticator does per assertion)
// before signing. userHandle is included (required for discoverable login).
func (a *softAuthenticator) loginRequest(t *testing.T, challenge string, userHandle []byte) *http.Request {
	t.Helper()
	a.signCount++
	return a.assertion(t, challenge, userHandle, a.signCount)
}

// assertionAtCount signs an assertion at a FIXED signature count without bumping the internal
// counter — used to forge a cloned/replayed authenticator (regressed counter).
func (a *softAuthenticator) assertionAtCount(t *testing.T, challenge string, userHandle []byte, count uint32) *http.Request {
	t.Helper()
	prev := a.signCount
	a.signCount = count
	req := a.assertion(t, challenge, userHandle, count)
	a.signCount = prev
	return req
}

func (a *softAuthenticator) assertion(t *testing.T, challenge string, userHandle []byte, count uint32) *http.Request {
	t.Helper()
	a.signCount = count
	authData := a.authData(t, flagUP|flagUV, false)
	cd := clientDataJSON(t, "webauthn.get", challenge, a.origin)
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
		"id":                     b64(a.credID),
		"rawId":                  b64(a.credID),
		"type":                   "public-key",
		"response":               resp,
		"clientExtensionResults": map[string]any{},
	}
	return jsonPost(t, body)
}

func jsonPost(t *testing.T, body map[string]any) *http.Request {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func userHandleOf(id uuid.UUID) []byte {
	b := id
	return b[:]
}
