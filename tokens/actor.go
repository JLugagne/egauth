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
// KeyID is always the key's own ID, and Scopes, Roles, and Groups are taken verbatim from the
// key's claims — egauth neither interprets nor enforces them; that is the application's middleware's
// job. No secret (token or hash) is ever copied onto the Actor.
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
		Roles:    key.Claims.Roles,
		Groups:   key.Claims.Groups,
	}

	switch key.Type {
	case KeyTypeService:
		// Machine identity: the subject is the key itself (already in KeyID); no owning user.
		actor.Kind = egauth.Service
	case KeyTypePAT:
		actor.Kind = egauth.PAT
		actor.UserID = key.Claims.Subject
	default:
		// Unclassified key: fail safe as a plain human principal, never as a machine.
		actor.Kind = egauth.User
		actor.UserID = key.Claims.Subject
	}

	return actor
}
