// Package repoguard holds repository-wide source guards that outlive any one API: every exported
// type with secret-shaped fields must redact itself from fmt and slog, published key literals must
// be on the secretpolicy denylist, and release tooling installs must be pinned.
package repoguard
