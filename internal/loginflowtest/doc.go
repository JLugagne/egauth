// Package loginflowtest holds the cross-flow conformance suite for the library's login and
// session-issuance paths.
//
// The suite enumerates every exported login entry point in one table (see loginFlows) and runs
// the same post-authentication invariant assertions against each of them: a disabled or
// deleted account cannot obtain a session, tenant binding fails closed, a forced password
// change survives issuance and cannot be cleared by the caller, a configured MFA gate withholds
// the full session until the second factor is verified, claims are rebuilt at issuance, an
// audit event is emitted, and every rejection path mints nothing. A flow that silently drops a
// control fails the corresponding subtest.
//
// Adding a login entry point means adding its constructor to the table (or recording an
// explicit exemption) or TestAllLoginFlowsRegistered fails. See flows_test.go.
package loginflowtest
