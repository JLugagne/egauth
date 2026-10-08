package memory

import (
	"time"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/identity"
)

func Age(st *Store, s principal.Subject, d time.Duration) {
	st.mu.Lock()
	defer st.mu.Unlock()
	back := func(t *time.Time) {
		if !t.IsZero() {
			*t = t.Add(-d)
		}
	}
	for i := range st.epochs {
		if st.epochs[i].change.Subject == s {
			back(&st.epochs[i].at)
		}
	}
	for _, r := range st.outbox {
		if r.item.Subject == s {
			back(&r.item.CreatedAt)
			back(&r.item.NextAttemptAt)
			back(&r.done)
		}
	}
	if a := st.accounts[s]; a != nil && a.password != nil {
		back(&a.password.lastFailure)
		back(&a.password.lockedUntil)
	}
}

func Unverified(st *Store, s principal.Subject, email identity.Identifier) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.accounts[s] = &account{user: identity.User{Subject: s, Email: email, CreatedAt: st.now()}}
}
