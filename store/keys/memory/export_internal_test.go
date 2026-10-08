package memory

import (
	"time"

	"github.com/JLugagne/egauth/store/keys"
)

func (s *Store) AddV016(k keys.Key) { s.addV016(k) }

func (s *Store) FeedLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.feed)
}

func (s *Store) BackdateFeed(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.feed {
		s.feed[i].at = s.feed[i].at.Add(-d)
	}
}
