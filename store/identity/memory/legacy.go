package memory

import (
	"context"
	"errors"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/identity"
)

func (s *Store) V016Identifiers(ctx context.Context, _ principal.Subject, limit int) ([]identity.V016Identifiers, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit < 1 {
		return nil, errors.Join(identity.ErrInvalidMutation, errors.New("limit must be positive"))
	}
	return []identity.V016Identifiers{}, nil
}

func (s *Store) CountLegacyIdentifiers(ctx context.Context) (int64, error) {
	return 0, ctx.Err()
}

func (s *Store) UpgradeIdentifiers(ctx context.Context, u identity.IdentifierUpgrade) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := identity.ValidateUpgrade(u); err != nil {
		return false, err
	}
	return false, nil
}
