package tokens

import "github.com/JLugagne/egauth"

// ActorFromAPIKey maps a verified API key to the egauth.Actor that classifies the request it
// authenticates. It is the single seam the verification, audit and middleware epics share so a
// verified key is always turned into the same Actor shape.
//
// The mapping follows the per-type subject model (see APIKey.Type / actor.go):
//
//   - KeyTypePAT     → Kind=egauth.PAT,     a human action. UserID is the owning user
//     (key.Claims.Subject); IsHuman() is true.
//   - KeyTypeService → Kind=egauth.Service, a machine action. The subject is the key's own
//     identity, carried in KeyID, so UserID is left zero; IsMachine() is true. The human who
//     created the key lives on APIKey.CreatedBy (for audit/attribution), not on the Actor.
//   - any other Type (including the zero value) defaults to egauth.User so an unclassified key
//     fails safe as a plain human principal rather than silently reading as a machine.
//
// KeyID is always the key's own ID and Scopes are taken verbatim from the key's claims — egauth
// neither interprets nor enforces them; that is the application's middleware's job. No secret
// (token or hash) is ever copied onto the Actor.
//
// The function lives in the tokens package because tokens already imports the root egauth package
// (for egauth.Actor); the root package must not import tokens in return (import cycle), so the
// mapper cannot live there.
func ActorFromAPIKey[C any](key *APIKey[C]) egauth.Actor {
	if key == nil {
		return egauth.Actor{}
	}

	actor := egauth.Actor{
		TenantID: key.TenantID,
		KeyID:    key.ID,
		Scopes:   key.Claims.Scopes,
		Kind:     PrincipalKindForKeyType(key.Type),
	}

	// A machine identity's subject IS the key (already in KeyID), so it has no owning user; every
	// human kind carries the owning/authenticated user.
	if actor.Kind != egauth.Service {
		actor.UserID = key.Claims.Subject
	}

	return actor
}

// PrincipalKindForKeyType maps an API-key type to the egauth.PrincipalKind that classifies the
// requests the key authenticates: KeyTypeService to egauth.Service, KeyTypePAT to egauth.PAT, and
// any other value (including the zero KeyType) to egauth.User, so an unclassified key fails safe as
// a plain human principal rather than silently reading as a machine.
//
// It is the single mapping shared by ActorFromAPIKey and the issuer, which stamps it on a key's
// Claims.Kind at issuance so the WithRequiredKind gate can enforce it.
func PrincipalKindForKeyType(keyType KeyType) egauth.PrincipalKind {
	switch keyType {
	case KeyTypeService:
		return egauth.Service
	case KeyTypePAT:
		return egauth.PAT
	default:
		return egauth.User
	}
}
