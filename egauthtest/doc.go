// Package egauthtest holds the test-only helpers of egauth: the development configuration, the
// principal builder, the manual clock, a capturing mailbox and a fake OIDC provider. It is the only
// sanctioned home of Insecure opt-outs and of the root test hooks, and the G15 guard fails any
// import of it from a non-test file, so a helper copied into a main package fails CI.
//
// # Stability
//
// Stability class: experimental. No SemVer guarantee: the API may change or be removed in any
// release. See docs/adr/0001-v1-scope-and-stability-classes.md.
package egauthtest
