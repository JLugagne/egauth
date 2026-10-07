package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"slices"
	"time"

	"github.com/google/uuid"
)

// MaxSealedLen bounds a sealed value accepted by Unseal and UnsealPending, in bytes.
const MaxSealedLen = 16 << 10

const (
	tagAttrs   byte = 'A'
	tagPending byte = 'P'
)

var (
	minUnixNano = time.Unix(0, math.MinInt64)
	maxUnixNano = time.Unix(0, math.MaxInt64)
)

// Sealed is the opaque persisted form of SessionAttrs or Pending (codec v1). Stores keep its bytes
// verbatim and never decode them.
type Sealed struct {
	b []byte
}

// SealedFromBytes wraps bytes read back from storage. It copies b and does not validate it;
// decoding happens only in Unseal and UnsealPending.
func SealedFromBytes(b []byte) Sealed {
	return Sealed{b: slices.Clone(b)}
}

// Bytes returns a copy of the sealed bytes for storage.
func (s Sealed) Bytes() []byte {
	return slices.Clone(s.b)
}

func (s Sealed) IsZero() bool {
	return len(s.b) == 0
}

// Seal encodes a with codec v1: a version byte, a type tag, then length-prefixed fields in a fixed
// order, factors as codes, times as Unix nanoseconds and the tenant as a string. It refuses with
// ErrInvalidArgument whatever Unseal would refuse, so every sealed value can be unsealed, and
// returns ErrMalformed for a time outside the codec range.
func Seal(a SessionAttrs) (Sealed, error) {
	if a.version == 0 {
		return Sealed{}, ErrInvalidArgument
	}
	if err := checkAttrs(a); err != nil {
		return Sealed{}, errors.Join(ErrInvalidArgument, err)
	}
	e := newEncoder(tagAttrs)
	e.uuid(a.lineage)
	e.subject(a.subject)
	e.factors(a.factors)
	e.count(len(a.credentialIDs))
	for _, u := range a.credentialIDs {
		e.str(u.factor.code)
		e.bytes(u.id)
	}
	e.time(a.primaryAt)
	e.time(a.secondAt)
	e.u64(a.epoch)
	e.bool(a.mustChange)
	e.bool(a.remember)
	e.str(a.returnTo)
	e.bytes([]byte{byte(a.transport)})
	e.str(a.provider)
	e.time(a.createdAt)
	e.time(a.claimsFetchedAt)
	return e.finish()
}

// Unseal decodes s. Its only allowed callers are internal/session, internal/issuance and
// internal/flow. It returns ErrMalformed unless s is the canonical v1 encoding of valid attributes.
func Unseal(s Sealed) (SessionAttrs, error) {
	d, err := newDecoder(s.b, tagAttrs)
	if err != nil {
		return SessionAttrs{}, err
	}
	a := SessionAttrs{version: codecVersion}
	a.lineage = d.uuid()
	a.subject = d.subject()
	a.factors = d.factors()
	n := d.count()
	for range n {
		f := d.factor()
		a.credentialIDs = append(a.credentialIDs, credentialUse{factor: f, id: d.bytes()})
	}
	a.primaryAt = d.time()
	a.secondAt = d.time()
	a.epoch = d.u64()
	a.mustChange = d.bool()
	a.remember = d.bool()
	a.returnTo = d.str()
	a.transport = d.transport()
	a.provider = d.str()
	a.createdAt = d.time()
	a.claimsFetchedAt = d.time()
	if err := d.done(); err != nil {
		return SessionAttrs{}, err
	}
	if err := checkAttrs(a); err != nil {
		return SessionAttrs{}, errors.Join(ErrMalformed, err)
	}
	if err := canonical(s.b, func() (Sealed, error) { return Seal(a) }); err != nil {
		return SessionAttrs{}, err
	}
	return a, nil
}

// SealPending encodes p with codec v1. It refuses with ErrInvalidArgument the zero Pending and
// whatever UnsealPending would refuse.
func SealPending(p Pending) (Sealed, error) {
	if p.version == 0 {
		return Sealed{}, ErrInvalidArgument
	}
	if err := checkPending(p); err != nil {
		return Sealed{}, errors.Join(ErrInvalidArgument, err)
	}
	e := newEncoder(tagPending)
	e.subjectTenant(p.tenant, p.subject.User)
	e.u64(p.epochAtBind)
	e.count(len(p.verified))
	for _, v := range p.verified {
		e.factors(v.factors)
		e.bytes(v.credentialID)
		e.bool(v.identifies)
		e.str(v.provider)
		e.time(v.at)
	}
	e.bool(p.remember)
	e.str(p.returnTo)
	e.bytes([]byte{byte(p.transport)})
	e.str(p.provider)
	e.uuid(p.reauthOf)
	e.bytes(p.bindHash)
	e.time(p.expiresAt)
	return e.finish()
}

// UnsealPending decodes s. It returns ErrMalformed unless s is the canonical v1 encoding of a
// valid Pending.
func UnsealPending(s Sealed) (Pending, error) {
	d, err := newDecoder(s.b, tagPending)
	if err != nil {
		return Pending{}, err
	}
	p := Pending{version: codecVersion}
	bound := d.subject()
	p.tenant = bound.Tenant
	if !bound.IsZero() {
		p.subject = bound
	}
	p.epochAtBind = d.u64()
	n := d.count()
	for range n {
		v := Verified{subject: p.subject}
		v.factors = d.factors()
		v.credentialID = d.bytes()
		v.identifies = d.bool()
		v.provider = d.str()
		v.at = d.time()
		p.verified = append(p.verified, v)
	}
	p.remember = d.bool()
	p.returnTo = d.str()
	p.transport = d.transport()
	p.provider = d.str()
	p.reauthOf = d.uuid()
	p.bindHash = d.bytes()
	p.expiresAt = d.time()
	if err := d.done(); err != nil {
		return Pending{}, err
	}
	if err := checkPending(p); err != nil {
		return Pending{}, errors.Join(ErrMalformed, err)
	}
	if err := canonical(s.b, func() (Sealed, error) { return SealPending(p) }); err != nil {
		return Pending{}, err
	}
	return p, nil
}

func checkAttrs(a SessionAttrs) error {
	if a.lineage == uuid.Nil || a.subject.IsZero() || !hasRole(a.factors, RolePrimary) || !a.transport.Valid() {
		return errors.New("invalid attributes")
	}
	for _, u := range a.credentialIDs {
		if (u.factor != FactorPasskey && u.factor != FactorPasskeyStepUp) || len(u.id) == 0 || !slices.Contains(a.factors, u.factor) {
			return errors.New("invalid credential use")
		}
	}
	return nil
}

func checkPending(p Pending) error {
	if !p.transport.Valid() || p.expiresAt.IsZero() || (len(p.verified) > 0 && !p.Bound()) {
		return errors.New("invalid pending")
	}
	for _, v := range p.verified {
		if v.at.IsZero() {
			return errors.New("invalid verified")
		}
		if err := checkVerifiedShape(v.factors, v.credentialID, v.identifies, v.provider); err != nil {
			return errors.Join(errors.New("invalid verified"), err)
		}
	}
	return nil
}

func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return slices.Clone(b)
}

func canonical(in []byte, reseal func() (Sealed, error)) error {
	out, err := reseal()
	if err != nil {
		return errors.Join(ErrMalformed, err)
	}
	if !bytes.Equal(out.b, in) {
		return errors.Join(ErrMalformed, errors.New("non-canonical encoding"))
	}
	return nil
}

type encoder struct {
	b   []byte
	err error
}

func newEncoder(tag byte) *encoder {
	return &encoder{b: []byte{codecVersion, tag}}
}

func (e *encoder) count(n int) {
	e.b = binary.AppendUvarint(e.b, uint64(n))
}

func (e *encoder) bytes(p []byte) {
	e.count(len(p))
	e.b = append(e.b, p...)
}

func (e *encoder) str(s string) {
	e.bytes([]byte(s))
}

func (e *encoder) u64(v uint64) {
	e.bytes(binary.BigEndian.AppendUint64(nil, v))
}

func (e *encoder) bool(v bool) {
	if v {
		e.bytes([]byte{1})
		return
	}
	e.bytes([]byte{0})
}

func (e *encoder) uuid(u uuid.UUID) {
	e.bytes(u[:])
}

func (e *encoder) time(t time.Time) {
	if t.IsZero() {
		e.bytes(nil)
		return
	}
	if t.Before(minUnixNano) || t.After(maxUnixNano) {
		e.err = errors.Join(ErrMalformed, errors.New("time out of codec range"))
		return
	}
	e.u64(uint64(t.UnixNano()))
}

func (e *encoder) subject(s Subject) {
	e.subjectTenant(s.Tenant, s.User)
}

func (e *encoder) subjectTenant(t TenantID, user uuid.UUID) {
	e.str(t.id)
	e.uuid(user)
}

func (e *encoder) factors(fs []Factor) {
	e.count(len(fs))
	for _, f := range fs {
		e.str(f.code)
	}
}

func (e *encoder) finish() (Sealed, error) {
	if e.err != nil {
		return Sealed{}, e.err
	}
	if len(e.b) > MaxSealedLen {
		return Sealed{}, errors.Join(ErrMalformed, errors.New("sealed value too large"))
	}
	return Sealed{b: e.b}, nil
}

type decoder struct {
	b   []byte
	err error
}

func newDecoder(b []byte, tag byte) (*decoder, error) {
	if len(b) < 2 || len(b) > MaxSealedLen {
		return nil, errors.Join(ErrMalformed, errors.New("length"))
	}
	if b[0] != codecVersion {
		return nil, errors.Join(ErrMalformed, errors.New("unsupported version"))
	}
	if b[1] != tag {
		return nil, errors.Join(ErrMalformed, errors.New("wrong type tag"))
	}
	return &decoder{b: b[2:]}, nil
}

func (d *decoder) fail(msg string) {
	if d.err == nil {
		d.err = errors.Join(ErrMalformed, errors.New(msg))
	}
	d.b = nil
}

func (d *decoder) count() int {
	if d.err != nil {
		return 0
	}
	n, k := binary.Uvarint(d.b)
	if k <= 0 || n > uint64(len(d.b)-k) {
		d.fail("bad length")
		return 0
	}
	d.b = d.b[k:]
	return int(n)
}

func (d *decoder) bytes() []byte {
	n := d.count()
	if d.err != nil {
		return nil
	}
	if n == 0 {
		return nil
	}
	out := slices.Clone(d.b[:n])
	d.b = d.b[n:]
	return out
}

func (d *decoder) fixed(size int) []byte {
	p := d.bytes()
	if d.err == nil && len(p) != size {
		d.fail("bad fixed field size")
		return nil
	}
	return p
}

func (d *decoder) str() string {
	return string(d.bytes())
}

func (d *decoder) u64() uint64 {
	p := d.fixed(8)
	if p == nil {
		return 0
	}
	return binary.BigEndian.Uint64(p)
}

func (d *decoder) bool() bool {
	p := d.fixed(1)
	if p == nil {
		return false
	}
	if p[0] > 1 {
		d.fail("bad bool")
	}
	return p[0] == 1
}

func (d *decoder) uuid() uuid.UUID {
	var u uuid.UUID
	copy(u[:], d.fixed(16))
	return u
}

func (d *decoder) time() time.Time {
	p := d.bytes()
	if d.err != nil || len(p) == 0 {
		return time.Time{}
	}
	if len(p) != 8 {
		d.fail("bad time")
		return time.Time{}
	}
	return time.Unix(0, int64(binary.BigEndian.Uint64(p))).UTC()
}

func (d *decoder) transport() Transport {
	p := d.fixed(1)
	if p == nil {
		return 0
	}
	return Transport(p[0])
}

func (d *decoder) subject() Subject {
	raw := d.str()
	user := d.uuid()
	if d.err != nil {
		return Subject{}
	}
	if raw == "" {
		return Subject{User: user}
	}
	t, err := ParseTenantID(raw)
	if err != nil {
		d.fail("bad tenant")
		return Subject{}
	}
	return Subject{Tenant: t, User: user}
}

func (d *decoder) factor() Factor {
	code := d.str()
	if d.err != nil {
		return Factor{}
	}
	f, err := FactorByCode(code)
	if err != nil {
		d.fail("unknown factor")
	}
	return f
}

func (d *decoder) factors() []Factor {
	n := d.count()
	var out []Factor
	for range n {
		f := d.factor()
		if d.err != nil {
			return nil
		}
		if len(out) > 0 && out[len(out)-1].code >= f.code {
			d.fail("factors not in canonical order")
			return nil
		}
		out = append(out, f)
	}
	return out
}

func (d *decoder) done() error {
	if d.err != nil {
		return d.err
	}
	if len(d.b) != 0 {
		return errors.Join(ErrMalformed, errors.New("trailing bytes"))
	}
	return nil
}
