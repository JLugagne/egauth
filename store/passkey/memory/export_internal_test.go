package memory

import "github.com/JLugagne/egauth/store/passkey"

func (s *Store) AddV016(c passkey.Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := clone(c)
	v.Discoverable = passkey.Legacy
	s.creds[key{c.Subject.Tenant, string(c.ID)}] = &v
}
