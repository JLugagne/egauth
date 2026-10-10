package journeytest

import (
	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/deployment"
	fedstore "github.com/JLugagne/egauth/store/federation"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/keys"
	"github.com/JLugagne/egauth/store/limiter"
	"github.com/JLugagne/egauth/store/mfa"
	"github.com/JLugagne/egauth/store/passkey"
	"github.com/JLugagne/egauth/store/sessions"
	"github.com/JLugagne/egauth/store/tokens"
)

type shared struct{}

func (shared) Durability() store.Durability { return store.Shared }

// SharedStorage returns st with every store reporting store.Shared, which is what a production
// deployment on persistent stores reports. It lets a World run the golden configuration on memory
// without the EphemeralState opt-out, which would otherwise be the one difference from production.
// The stores are wrapped in anonymous types, so no declared type here is a store implementation
// that would need its own contract suite.
func SharedStorage(st egauth.Storage) egauth.Storage {
	type identityStore struct{ identity.Store }
	type ceremonyStore struct{ ceremony.Store }
	type deploymentStore struct{ deployment.Store }
	type limiterStore struct{ limiter.Limiter }
	type tokensStore struct{ tokens.Store }
	type sessionsStore struct{ sessions.Store }
	type mfaStore struct{ mfa.Store }
	type passkeyStore struct{ passkey.Store }
	type federationStore struct{ fedstore.Store }
	type keysStore struct{ keys.Store }
	return egauth.Storage{
		Identity: struct {
			identityStore
			shared
		}{identityStore{st.Identity}, shared{}},
		Ceremonies: struct {
			ceremonyStore
			shared
		}{ceremonyStore{st.Ceremonies}, shared{}},
		Deployment: struct {
			deploymentStore
			shared
		}{deploymentStore{st.Deployment}, shared{}},
		Limiter: struct {
			limiterStore
			shared
		}{limiterStore{st.Limiter}, shared{}},
		Tokens: struct {
			tokensStore
			shared
		}{tokensStore{st.Tokens}, shared{}},
		Sessions: struct {
			sessionsStore
			shared
		}{sessionsStore{st.Sessions}, shared{}},
		MFA: struct {
			mfaStore
			shared
		}{mfaStore{st.MFA}, shared{}},
		Passkeys: struct {
			passkeyStore
			shared
		}{passkeyStore{st.Passkeys}, shared{}},
		Federation: struct {
			federationStore
			shared
		}{federationStore{st.Federation}, shared{}},
		Keys: struct {
			keysStore
			shared
		}{keysStore{st.Keys}, shared{}},
	}
}
