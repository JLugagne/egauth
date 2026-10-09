package passkeysvc

import (
	"context"

	"github.com/JLugagne/egauth/internal/core"
)

// FinishReauth is FinishStepUp for /reauth (DESIGN §5.3): the MFAPasskey record of handle must seal
// a reauthentication Pending begun with BeginStepUp, and the assertion yields pk and uv, the single
// ceremony that proves both factors. The caller must refuse the result unless the returned Pending
// reauthenticates the session it serves (same subject and lineage). It returns ErrPasskeyRejected,
// also for a record begun from a login, or a 503 problem.
func (s *Service) FinishReauth(ctx context.Context, t core.TenantID, handle string, assertionJSON []byte) (core.Pending, core.Verified, error) {
	return s.finishSubjectAssertion(ctx, t, handle, assertionJSON, true)
}
