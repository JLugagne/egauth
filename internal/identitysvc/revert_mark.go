package identitysvc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
)

const (
	revertSpans = 5
	revertLease = time.Minute
)

var (
	labelRevertLink    = []byte("egauth/security-revert/link/v1")
	labelRevertAnchor  = []byte("egauth/security-revert/anchor/v1")
	labelRevertSpan    = []byte("egauth/security-revert/span/v1")
	labelRevertTenure  = []byte("egauth/security-revert/tenure/v1")
	labelRevertLock    = []byte("egauth/security-revert/lock/v1")
	errRevertBusy      = errors.New("identitysvc: another security revert of this account is running")
	errAnchorContended = errors.New("identitysvc: revert anchor kept changing")
)

type tenure struct {
	hash     []byte
	live     bool
	addr     string
	from, to time.Time
}

type revertSpan struct {
	hash     []byte
	live     bool
	from, to time.Time
}

func (a *Accounts) keyed(label []byte, sub core.Subject, parts ...[]byte) []byte {
	mac := hmac.New(sha256.New, a.scopes.key)
	for _, p := range append([][]byte{label, []byte(sub.Tenant.String()), sub.User[:]}, parts...) {
		mac.Write(binary.BigEndian.AppendUint32(nil, uint32(len(p))))
		mac.Write(p)
	}
	return mac.Sum(nil)
}

func (a *Accounts) revertHandle(item identity.OutboxItem) (ceremonycodec.Handle, error) {
	id := noticeDeliveryID(item)
	raw := a.keyed(labelRevertLink, item.Subject, id[:])
	return ceremonycodec.ParseHandle(base64.RawURLEncoding.EncodeToString(raw))
}

func (a *Accounts) revertRecord(ctx context.Context, u identity.User, scope ceremony.Scope, hash []byte, rv ceremonycodec.Revert, now time.Time) (ceremony.Record, error) {
	p, err := a.pendings.Detached(ctx, u.Subject.Tenant)
	if err != nil {
		return ceremony.Record{}, err
	}
	if p, err = p.Bind(u.Subject, stateOf(u)); err != nil {
		return ceremony.Record{}, err
	}
	payload, err := ceremonycodec.SecurityRevert().Encode(rv)
	if err != nil {
		return ceremony.Record{}, err
	}
	sealed, err := core.SealPending(p)
	if err != nil {
		return ceremony.Record{}, err
	}
	return ceremony.NewRecord(ceremony.Spec{
		Kind: ceremony.SecurityRevert, HandleHash: hash, Scope: scope, Pending: sealed, Payload: payload, Now: now,
	}, openPending)
}

func (a *Accounts) putMark(ctx context.Context, u identity.User, scopeMAC, hash []byte, note string, now time.Time) error {
	scope, err := ceremony.IdentifierScope(scopeMAC)
	if err != nil {
		return err
	}
	rec, err := a.revertRecord(ctx, u, scope, hash, ceremonycodec.Revert{Address: note, Event: uint16(SecurityIdentifierChanged)}, now)
	if err != nil {
		return err
	}
	_, err = a.ceremonies.Put(ctx, rec)
	return err
}

func (a *Accounts) peekMark(ctx context.Context, t core.TenantID, hash []byte) (ceremony.Record, bool, error) {
	rec, err := a.ceremonies.Peek(ctx, t, ceremony.SecurityRevert, hash)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ceremony.Record{}, false, nil
	case err != nil:
		return ceremony.Record{}, false, err
	}
	return rec, true, nil
}

func (a *Accounts) anchorKeys(sub core.Subject, addr identity.Identifier) (scope []byte, slots [2][]byte) {
	v := []byte(addr.Value())
	for i := range slots {
		slots[i] = a.keyed(labelRevertAnchor, sub, v, []byte{byte(i)})
	}
	return a.keyed(labelRevertAnchor, sub, v), slots
}

func (a *Accounts) anchor(ctx context.Context, sub core.Subject, addr identity.Identifier) (first, last time.Time, live [2]bool, err error) {
	_, slots := a.anchorKeys(sub, addr)
	for i, hash := range slots {
		rec, ok, err := a.peekMark(ctx, sub.Tenant, hash)
		if err != nil {
			return time.Time{}, time.Time{}, live, err
		}
		if !ok {
			continue
		}
		live[i] = true
		from, at := rec.CreatedAt(), rec.CreatedAt()
		if f, ok := markedFrom(rec); ok && f.Before(from) {
			from = f
		}
		if first.IsZero() || from.Before(first) {
			first = from
		}
		if at.After(last) {
			last = at
		}
	}
	return first, last, live, nil
}

func markedFrom(rec ceremony.Record) (time.Time, bool) {
	rv, err := ceremonycodec.SecurityRevert().Decode(rec.Payload())
	if err != nil {
		return time.Time{}, false
	}
	us, err := strconv.ParseInt(rv.Address, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.UnixMicro(us), true
}

func (a *Accounts) holdAnchor(ctx context.Context, u identity.User, addr identity.Identifier, at time.Time) error {
	sub := u.Subject
	scope, slots := a.anchorKeys(sub, addr)
	at = at.Round(0).Truncate(time.Microsecond)
	for range 3 {
		first, last, live, err := a.anchor(ctx, sub, addr)
		if err != nil {
			return err
		}
		held := live[0] || live[1]
		if held && !first.After(at) && !last.Before(at) {
			return nil
		}
		start, end := at, at
		if held {
			start, end = minTime(first, at), maxTime(last, at)
		}
		slot := 0
		if live[0] {
			slot = 1
		}
		if live[slot] {
			if err := a.consumeMark(ctx, sub.Tenant, slots[slot]); err != nil {
				return err
			}
		}
		err = a.putMark(ctx, u, scope, slots[slot], strconv.FormatInt(start.UnixMicro(), 10), end)
		switch {
		case errors.Is(err, store.ErrConflict):
			continue
		case err != nil:
			return err
		}
		if live[1-slot] {
			if err := a.consumeMark(ctx, sub.Tenant, slots[1-slot]); err != nil {
				return err
			}
		}
		return nil
	}
	return errAnchorContended
}

func (a *Accounts) consumeMark(ctx context.Context, t core.TenantID, hash []byte) error {
	if _, err := a.ceremonies.Consume(ctx, t, ceremony.SecurityRevert, hash); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func (a *Accounts) dropAnchor(ctx context.Context, sub core.Subject, addr identity.Identifier) {
	if addr.IsZero() {
		return
	}
	_, slots := a.anchorKeys(sub, addr)
	for _, hash := range slots {
		_ = a.consumeMark(ctx, sub.Tenant, hash)
	}
}

func (a *Accounts) spans(ctx context.Context, sub core.Subject) ([revertSpans]revertSpan, error) {
	var out [revertSpans]revertSpan
	for i := range out {
		out[i].hash = a.keyed(labelRevertSpan, sub, []byte{byte(i)})
		rec, ok, err := a.peekMark(ctx, sub.Tenant, out[i].hash)
		if err != nil {
			return out, err
		}
		if !ok {
			continue
		}
		out[i].live, out[i].to = true, rec.CreatedAt()
		out[i].from, _ = markedFrom(rec)
	}
	return out, nil
}

func (a *Accounts) superseded(ctx context.Context, sub core.Subject, changedAt time.Time) (bool, error) {
	all, err := a.spans(ctx, sub)
	if err != nil {
		return false, err
	}
	for _, s := range all {
		if s.live && !changedAt.Before(s.from) && !changedAt.After(s.to) {
			return true, nil
		}
	}
	return false, nil
}

func (a *Accounts) spanWidens(ctx context.Context, sub core.Subject, from, to time.Time) (bool, error) {
	all, err := a.spans(ctx, sub)
	if err != nil {
		return false, err
	}
	_, widens := pickSpan(all, from, to)
	return widens, nil
}

func pickSpan(all [revertSpans]revertSpan, from, to time.Time) (int, bool) {
	free, latest := -1, 0
	for i, s := range all {
		switch {
		case !s.live:
			if free < 0 {
				free = i
			}
		case !s.from.After(to) && !from.After(s.to):
			return i, false
		case s.to.After(all[latest].to):
			latest = i
		}
	}
	if free >= 0 {
		return free, false
	}
	return latest, true
}

func (a *Accounts) recordSpan(ctx context.Context, u identity.User, from, to time.Time) error {
	sub := u.Subject
	scope := a.keyed(labelRevertSpan, sub)
	var err error
	for range revertSpans {
		var all [revertSpans]revertSpan
		if all, err = a.spans(ctx, sub); err != nil {
			return err
		}
		slot, _ := pickSpan(all, from, to)
		start, end := from, to
		if old := all[slot]; old.live {
			if err := a.consumeMark(ctx, sub.Tenant, old.hash); err != nil {
				return err
			}
			if old.from.Before(start) {
				start = old.from
			}
			if old.to.After(end) {
				end = old.to
			}
		}
		note := strconv.FormatInt(start.UnixMicro(), 10)
		if err = a.putMark(ctx, u, scope, all[slot].hash, note, end); !errors.Is(err, store.ErrConflict) {
			return err
		}
	}
	return err
}

func (a *Accounts) lockReverts(ctx context.Context, u identity.User) (func(), error) {
	sub := u.Subject
	hash := a.keyed(labelRevertLock, sub, []byte{0})
	held := a.clock.Now().Add(revertLease - ceremony.SecurityRevert.TTL())
	err := a.putMark(ctx, u, a.keyed(labelRevertLock, sub), hash, "lock", held)
	switch {
	case errors.Is(err, store.ErrConflict):
		return nil, errors.Join(httpx.ErrServiceUnavailable, errRevertBusy)
	case err != nil:
		return nil, errors.Join(httpx.ErrServiceUnavailable, err)
	}
	return func() { _ = a.consumeMark(context.WithoutCancel(ctx), sub.Tenant, hash) }, nil
}

func emailChangeOf(ap identity.Applied) (identity.Identifier, time.Time, bool) {
	for _, it := range ap.Outbox {
		if it.Event == identity.EventIdentifierChanged && it.Identifier == identity.IdentifierEmail && !it.CreatedAt.IsZero() {
			return it.Old, it.CreatedAt, !it.Old.IsZero()
		}
	}
	return identity.Identifier{}, time.Time{}, false
}

func (a *Accounts) recordTenure(ctx context.Context, before identity.User, ap identity.Applied) error {
	old, end, ok := emailChangeOf(ap)
	if !ok || old != before.Email || before.EmailVerifiedAt.IsZero() || !before.EmailVerifiedAt.Before(end) {
		return nil
	}
	sub := before.Subject
	scope := a.keyed(labelRevertTenure, sub)
	note := strconv.FormatInt(before.EmailVerifiedAt.UnixMicro(), 10) + " " + old.Value()
	var err error
	for range revertSpans {
		var all [revertSpans]tenure
		if all, err = a.tenures(ctx, sub); err != nil {
			return err
		}
		slot := oldestTenure(all)
		if all[slot].live {
			if err := a.consumeMark(ctx, sub.Tenant, all[slot].hash); err != nil {
				return err
			}
		}
		if err = a.putMark(ctx, before, scope, all[slot].hash, note, end); !errors.Is(err, store.ErrConflict) {
			return err
		}
	}
	return err
}

func oldestTenure(all [revertSpans]tenure) int {
	oldest := 0
	for i, e := range all {
		if !e.live {
			return i
		}
		if e.to.Before(all[oldest].to) {
			oldest = i
		}
	}
	return oldest
}

func (a *Accounts) tenures(ctx context.Context, sub core.Subject) ([revertSpans]tenure, error) {
	var out [revertSpans]tenure
	for i := range out {
		out[i].hash = a.keyed(labelRevertTenure, sub, []byte{byte(i)})
		rec, ok, err := a.peekMark(ctx, sub.Tenant, out[i].hash)
		if err != nil {
			return out, err
		}
		if !ok {
			continue
		}
		out[i].live = true
		rv, err := ceremonycodec.SecurityRevert().Decode(rec.Payload())
		if err != nil {
			continue
		}
		from, addr, found := strings.Cut(rv.Address, " ")
		if us, err := strconv.ParseInt(from, 10, 64); found && err == nil {
			out[i].addr, out[i].from, out[i].to = addr, time.UnixMicro(us), rec.CreatedAt()
		}
	}
	return out, nil
}

func (a *Accounts) emailAt(ctx context.Context, sub core.Subject, at time.Time) (identity.Identifier, bool, error) {
	all, err := a.tenures(ctx, sub)
	if err != nil {
		return identity.Identifier{}, false, err
	}
	for _, e := range all {
		if !e.live || e.to.IsZero() || at.Before(e.from) || !at.Before(e.to) {
			continue
		}
		addr, err := identity.NewIdentifier(identity.IdentifierEmail, e.addr)
		if err != nil {
			return identity.Identifier{}, false, nil
		}
		return addr, true, nil
	}
	return identity.Identifier{}, false, nil
}
