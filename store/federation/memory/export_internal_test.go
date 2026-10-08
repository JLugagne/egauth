package memory

import (
	"github.com/JLugagne/egauth/store/federation"
)

func (s *Store) AddV016(p federation.ProviderSpec) { s.addV016(p) }
