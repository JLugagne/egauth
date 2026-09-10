// Package issuance is the single post-authentication credential-minting pipeline. Every
// interactive login flow — password, magic link, OAuth callback, passkey, OTP, MFA step-up,
// the unified authflow engine — terminates here instead of calling tokens.Issuer.IssueTokenPair
// directly, so the post-authentication invariants are applied exactly once:
//
//   - the account state is re-loaded authoritatively at issuance time (deleted and disabled
//     accounts are rejected here, not only in the credential verifier);
//   - the resolved account is bound to the requested tenant (a mismatch fails closed instead of
//     silently minting into another partition);
//   - MustChangePassword is computed from the authoritative state and OR-ed with the caller's
//     signal, so a caller can add the flag but never clear it;
//   - the MFA gate is applied in one place, and constructing a pipeline with a gate but no
//     authoritative state source fails loudly rather than silently skipping the account check;
//   - claims are re-evaluated at issuance (the configured claims builder runs immediately
//     before this package is invoked) and the authoritative subject/tenant/must-change fields
//     are stamped over them;
//   - the refresh family records the tenant, must-change flag and auth time consistently,
//     because those fields are written onto the claims this package hands to the issuer;
//   - one uniform SessionIssued audit event is emitted regardless of which flow minted the
//     credential.
//
// The package depends only on tokens (plus the dependency-free event and uuid packages), so any
// module can use it without an import cycle. The identity package implements the Resolver
// interface against its store and is the reference caller.
package issuance
