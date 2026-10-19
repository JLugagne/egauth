package scripts_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	return filepath.Dir(wd)
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(dst), 0o755))
	require.NoError(t, os.WriteFile(dst, data, 0o644))
}

func fixture(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts are exercised on unix runners only")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	root := repoRoot(t)
	files := []string{
		"VERSION", "go.mod", "adapters/pgx/go.mod", "adapters/otel/go.mod",
		"RELEASING.md", "CONTRIBUTING.md", "Makefile", ".github/workflows/ci.yml",
		"scripts/consumer-smoke.sh", "scripts/sync-versions.sh",
	}
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(root, f)); err != nil {
			t.Skipf("%s is not part of this module distribution", f)
		}
	}
	dir := t.TempDir()
	for _, f := range files {
		copyFile(t, filepath.Join(root, f), filepath.Join(dir, f))
	}
	return dir
}

func coreRequire(t *testing.T, dir string) string {
	t.Helper()
	v, err := os.ReadFile(filepath.Join(dir, "VERSION"))
	require.NoError(t, err)
	return "github.com/JLugagne/egauth v" + strings.TrimSpace(string(v))
}

func runCheck(t *testing.T, dir string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", filepath.Join(dir, "scripts/sync-versions.sh"), "--check")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func rewrite(t *testing.T, path string, mutate func(string) string) {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte(mutate(string(data))), 0o644))
}

func TestSyncVersions_CleanTreePasses(t *testing.T) {
	out, err := runCheck(t, fixture(t))
	require.NoError(t, err, out)
}

func TestSyncVersions_DetectsDrift(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string){
		"version bump leaves siblings behind": func(t *testing.T, dir string) {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "VERSION"), []byte("0.99.0\n"), 0o644))
		},
		"pgx require drifts": func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, "adapters/pgx/go.mod"), func(s string) string {
				return strings.Replace(s, "egauth v0.", "egauth v9.", 1)
			})
		},
		"otel require drifts": func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, "adapters/otel/go.mod"), func(s string) string {
				return strings.Replace(s, "egauth v0.", "egauth v9.", 1)
			})
		},
		"smoke CORE_VERSION drifts": func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, "scripts/consumer-smoke.sh"), func(s string) string {
				return strings.Replace(s, "CORE_VERSION='v", "CORE_VERSION='v9.", 1)
			})
		},
		"stale replace comment in root go.mod": func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, "go.mod"), func(s string) string {
				return s + "\n// The replace below resolves the adapter locally.\n"
			})
		},
		"core requires an adapter (cycle) at a stale version": func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, "go.mod"), func(s string) string {
				return s + "\nrequire github.com/JLugagne/egauth/adapters/pgx v0.16.0\n"
			})
		},
		"core requires an adapter inside a require block": func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, "go.mod"), func(s string) string {
				return s + "\nrequire (\n\tgithub.com/JLugagne/egauth/adapters/otel v0.16.0 // indirect\n)\n"
			})
		},
		"pgx requires otel": func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, "adapters/pgx/go.mod"), func(s string) string {
				return s + "\nrequire github.com/JLugagne/egauth/adapters/otel v0.16.0\n"
			})
		},
		"otel requires pgx": func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, "adapters/otel/go.mod"), func(s string) string {
				return s + "\nrequire github.com/JLugagne/egauth/adapters/pgx v0.16.0\n"
			})
		},
		"smoke reassigns CORE_VERSION later": func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, "scripts/consumer-smoke.sh"), func(s string) string {
				return s + "\nCORE_VERSION=\"v0.16.0\"\n"
			})
		},
		"adapter replaces core with a published version": func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, "adapters/pgx/go.mod"), func(s string) string {
				return s + "\nreplace github.com/JLugagne/egauth => github.com/JLugagne/egauth v0.16.0\n"
			})
		},
		"trailing comment mentions replace without a directive": func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, "adapters/otel/go.mod"), func(s string) string {
				var keep []string
				for l := range strings.SplitSeq(s, "\n") {
					if !strings.Contains(l, "replace") {
						keep = append(keep, l)
					}
				}
				return strings.Replace(strings.Join(keep, "\n"), coreRequire(t, dir), coreRequire(t, dir)+" // pinned; see the replace below", 1)
			})
		},
		"stale require hidden behind a version-qualified replace block": func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, "adapters/otel/go.mod"), func(s string) string {
				s = strings.Replace(s, "\nrequire", "\nreplace (\n\t"+coreRequire(t, dir)+" => ../..\n)\n\nrequire", 1)
				return strings.Replace(s, "\t"+coreRequire(t, dir)+"\n", "\tgithub.com/JLugagne/egauth v0.16.0\n", 1)
			})
		},
		"comment containing an arrow hides a missing replace directive": func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, "adapters/otel/go.mod"), func(s string) string {
				var keep []string
				for l := range strings.SplitSeq(s, "\n") {
					if !strings.Contains(l, "replace") || strings.HasPrefix(l, "//") {
						keep = append(keep, l)
					}
				}
				return strings.Join(keep, "\n") + "\nrequire go.opentelemetry.io/otel v1.46.0 // bumped => v1.46\n// The replace below resolves the core module.\n"
			})
		},
		"smoke readonly reassignment": func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, "scripts/consumer-smoke.sh"), func(s string) string {
				return s + "\nreadonly CORE_VERSION='v0.16.0'\n"
			})
		},
		"smoke local reassignment": func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, "scripts/consumer-smoke.sh"), func(s string) string {
				return s + "\nlocal CORE_VERSION=v0.16.0\n"
			})
		},
		"smoke declare reassignment": func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, "scripts/consumer-smoke.sh"), func(s string) string {
				return s + "\ndeclare -r CORE_VERSION=v0.16.0\n"
			})
		},
		"CI pins a different govulncheck": func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, ".github/workflows/ci.yml"), func(s string) string {
				return s + "\n# run: go run golang.org/x/vuln/cmd/govulncheck@v0.0.1 ./...\n"
			})
		},
		"RELEASING.md pins a different syft": func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, "RELEASING.md"), func(s string) string {
				return strings.Replace(s, "syft@v", "syft@v9.", 1)
			})
		},
		"RELEASING.md pins a different cosign": func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, "RELEASING.md"), func(s string) string {
				return strings.Replace(s, "cosign@v", "cosign@v9.", 1)
			})
		},
		"smoke does not build a published module": func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, "scripts/consumer-smoke.sh"), func(s string) string {
				return strings.ReplaceAll(s, "adapters/otel", "adapters/gone")
			})
		},
		"RELEASING.md never names the core module": func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, "RELEASING.md"), func(s string) string {
				return strings.ReplaceAll(s, "github.com/JLugagne/egauth", "github.com/JLugagne/egauth/adapters/pgx")
			})
		},
		"RELEASING.md omits otel": func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, "RELEASING.md"), func(s string) string {
				return strings.ReplaceAll(s, "adapters/otel", "adapters/removed")
			})
		},
		"RELEASING.md omits tools statement": func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, "RELEASING.md"), func(s string) string {
				return strings.ReplaceAll(s, "unpublished", "internal")
			})
		},
	}
	want := map[string]string{
		"version bump leaves siblings behind":                           "requires",
		"pgx require drifts":                                            "adapters/pgx/go.mod requires",
		"otel require drifts":                                           "adapters/otel/go.mod requires",
		"smoke CORE_VERSION drifts":                                     "CORE_VERSION is",
		"stale replace comment in root go.mod":                          "go.mod has a comment mentioning replace",
		"core requires an adapter (cycle) at a stale version":           "requires sibling module",
		"core requires an adapter inside a require block":               "requires sibling module",
		"pgx requires otel":                                             "requires sibling module",
		"otel requires pgx":                                             "requires sibling module",
		"smoke reassigns CORE_VERSION later":                            "CORE_VERSION is v0.16.0",
		"adapter replaces core with a published version":                "replaces",
		"trailing comment mentions replace without a directive":         "comment mentioning replace",
		"stale require hidden behind a version-qualified replace block": "adapters/otel/go.mod requires",
		"comment containing an arrow hides a missing replace directive": "comment mentioning replace",
		"smoke readonly reassignment":                                   "CORE_VERSION is v0.16.0",
		"smoke local reassignment":                                      "CORE_VERSION is v0.16.0",
		"smoke declare reassignment":                                    "CORE_VERSION is v0.16.0",
		"CI pins a different govulncheck":                               "ci.yml pins govulncheck",
		"RELEASING.md pins a different syft":                            "RELEASING.md pins syft",
		"RELEASING.md pins a different cosign":                          "RELEASING.md pins cosign",
		"smoke does not build a published module":                       "does not build published module",
		"RELEASING.md never names the core module":                      "does not name the core module",
		"RELEASING.md omits otel":                                       "does not name published module",
		"RELEASING.md omits tools statement":                            "tools module is unpublished",
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			substr, ok := want[name]
			require.True(t, ok, "case needs an expected DRIFT message")
			dir := fixture(t)
			mutate(t, dir)
			out, err := runCheck(t, dir)
			require.Error(t, err, out)
			require.Contains(t, out, "DRIFT:")
			require.Contains(t, out, substr)
		})
	}
}

func TestSyncVersions_RewriteFixesDrift(t *testing.T) {
	dir := fixture(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "VERSION"), []byte("0.99.0\n"), 0o644))
	out, err := runRewrite(t, dir)
	require.NoError(t, err, out)
	out2, err := runCheck(t, dir)
	require.NoError(t, err, out2)
}

func runRewrite(t *testing.T, dir string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", filepath.Join(dir, "scripts/sync-versions.sh"))
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestSyncVersions_RewriteHandlesSingleLineRequire(t *testing.T) {
	dir := fixture(t)
	rewrite(t, filepath.Join(dir, "adapters/otel/go.mod"), func(s string) string {
		s = strings.Replace(s, "\tgithub.com/JLugagne/egauth v", "\tgithub.com/JLugagne/egauth/adapters/x v", 1)
		return s + "\nrequire github.com/JLugagne/egauth v0.16.0\n"
	})
	out, err := runRewrite(t, dir)
	require.NoError(t, err, out)
	data, err := os.ReadFile(filepath.Join(dir, "adapters/otel/go.mod"))
	require.NoError(t, err)
	require.Contains(t, string(data), "require "+coreRequire(t, dir))
}

func TestSyncVersions_DocumentedReleaseStepsStayInSync(t *testing.T) {
	dir := fixture(t)
	releasing, err := os.ReadFile(filepath.Join(dir, "RELEASING.md"))
	require.NoError(t, err)
	const dropComment = "/^\\/\\/ The `replace` below/,/^\\/\\/ against the published core tag/d"
	require.Contains(t, string(releasing), dropComment)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "VERSION"), []byte("0.17.0\n"), 0o644))
	out, err := runRewrite(t, dir)
	require.NoError(t, err, out)
	for _, mod := range []string{"adapters/pgx", "adapters/otel"} {
		gomod := filepath.Join(dir, mod, "go.mod")
		for _, args := range [][]string{
			{"-i.bak", dropComment, gomod},
			{"-i.bak", "/^replace github.com\\/JLugagne\\/egauth => /d", gomod},
		} {
			cmd := exec.Command("sed", args...)
			sedOut, err := cmd.CombinedOutput()
			require.NoError(t, err, string(sedOut))
		}
	}
	out, err = runCheck(t, dir)
	require.NoError(t, err, out)
}
