package memory

import (
	"bytes"
	"time"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/mfa"
)

func (s *Store) AddV016(sub principal.Subject, sealed []byte, createdAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	s.totp[sub] = &totpRow{
		seq: s.seq,
		Enrollment: mfa.Enrollment{
			Subject: sub, Sealed: bytes.Clone(sealed), AADVersion: mfa.AADVersionLegacy,
			CreatedAt: createdAt.UTC().Truncate(time.Microsecond),
		},
	}
}
