package memory

import (
	"time"

	"github.com/JLugagne/egauth/principal"
)

func (s *Store) AddV016(sub principal.Subject, sealed []byte, createdAt time.Time) {
	s.addV016(sub, sealed, createdAt)
}
