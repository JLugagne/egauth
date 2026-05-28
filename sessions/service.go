package sessions

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Service defines the business logic for session management.
type Service interface {
	CreateSession(ctx context.Context, userID uuid.UUID, tenantID string, userAgent string, ip string, duration time.Duration) (*Session, string, error)
	ValidateSession(ctx context.Context, token string, opts ...Option) (*Session, error)
	RevokeSession(ctx context.Context, token string, opts ...Option) error
}

type service struct {
	store Store
}

// NewService creates a new sessions Service.
func NewService(store Store) Service {
	return &service{
		store: store,
	}
}

func (s *service) CreateSession(ctx context.Context, userID uuid.UUID, tenantID string, userAgent string, ip string, duration time.Duration) (*Session, string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, "", fmt.Errorf("failed to generate random session token: %w", err)
	}

	token := hex.EncodeToString(tokenBytes)
	hash := s.hashToken(token)

	session := &Session{
		ID:        uuid.New(),
		TenantID:  tenantID,
		UserID:    userID,
		TokenHash: hash,
		UserAgent: userAgent,
		IP:        ip,
		ExpiresAt: time.Now().Add(duration),
		CreatedAt: time.Now(),
	}

	if err := s.store.CreateSession(ctx, session, WithTenant(tenantID)); err != nil {
		return nil, "", err
	}

	return session, token, nil
}

func (s *service) ValidateSession(ctx context.Context, token string, opts ...Option) (*Session, error) {
	hash := s.hashToken(token)

	session, err := s.store.FindSessionByHash(ctx, hash, opts...)
	if err != nil {
		return nil, err
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionNotFound
	}

	return session, nil
}

func (s *service) RevokeSession(ctx context.Context, token string, opts ...Option) error {
	hash := s.hashToken(token)

	session, err := s.store.FindSessionByHash(ctx, hash, opts...)
	if err != nil {
		return err
	}

	return s.store.DeleteSession(ctx, session.ID, WithTenant(session.TenantID))
}

func (s *service) hashToken(token string) string {
	h := sha256.New()
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}
