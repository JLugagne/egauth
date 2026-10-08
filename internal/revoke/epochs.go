package revoke

import (
	"context"
	"errors"
	"strconv"

	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
)

// EpochSource is the part of identity.Store the epoch cache reads.
type EpochSource interface {
	CurrentEpoch(ctx context.Context, s principal.Subject) (uint64, error)
	EpochsChangedSince(ctx context.Context, c store.Cursor) ([]identity.EpochChange, store.Cursor, error)
}

// Epochs caches subjects' security epochs, following EpochsChangedSince. It is safe for concurrent
// use.
type Epochs struct {
	*follower[principal.Subject, uint64]
}

// NewEpochs returns a stopped epoch cache over src. It returns ErrInvalidConfig for a nil src or a
// negative capacity.
func NewEpochs(src EpochSource, cfg Config) (*Epochs, error) {
	if src == nil {
		return nil, errors.Join(ErrInvalidConfig, errors.New("revoke: nil epoch source"))
	}
	feed := func(ctx context.Context, c store.Cursor) ([]principal.Subject, store.Cursor, error) {
		changes, next, err := src.EpochsChangedSince(ctx, c)
		if err != nil {
			return nil, c, err
		}
		out := make([]principal.Subject, len(changes))
		for i, ch := range changes {
			out[i] = ch.Subject
		}
		return out, next, nil
	}
	scope := func(s principal.Subject) audit.Scope {
		return audit.Scope{TenantID: s.Tenant.String(), UserID: s.User.String()}
	}
	f, err := newFollower("epochs", cfg, feed, src.CurrentEpoch, scope)
	if err != nil {
		return nil, err
	}
	return &Epochs{follower: f}, nil
}

// Current returns the security epoch of s. It returns an error wrapping store.ErrNotFound for an
// unknown subject and ErrUnavailable when the store cannot answer.
func (e *Epochs) Current(ctx context.Context, s principal.Subject) (uint64, error) {
	return e.get(ctx, s)
}

// Check returns nil when sealed is the current security epoch of s, ErrStaleEpoch when it is not or
// s does not exist, and ErrUnavailable when the store cannot answer.
func (e *Epochs) Check(ctx context.Context, s principal.Subject, sealed uint64) error {
	cur, err := e.get(ctx, s)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return errors.Join(ErrStaleEpoch, err)
		}
		return err
	}
	if cur != sealed {
		return errors.Join(ErrStaleEpoch, errors.New("revoke: sealed epoch "+strconv.FormatUint(sealed, 10)+", current "+strconv.FormatUint(cur, 10)))
	}
	return nil
}
