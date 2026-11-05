//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	knobe "github.com/KnobeDev/knobe-go"
	"github.com/KnobeDev/knobe-go/internal/lenstest"
)

// Path probes: file names lens.py has to show in a reason. Python holds a
// command-line path decoded with surrogateescape, so a byte that is not
// UTF-8 shows as \udcXX; the patched lens.py escapes names like any other
// text (safe()), and an OSError shows repr() of the name.

// nameVariants are the hostile parts of a probe's file name.
var nameVariants = map[string]string{
	"non-utf8": "\xff",
	"ansi":     "\x1b[31m",
	"bidi":     "\u202e",
	"quote":    "'q",
}

type pathProbe struct {
	name, path string
	// pending is set when a lens.py without the display patch prints this
	// differently (or crashes), in --json and human form alike.
	pending string
}

const (
	pendingPathSafe  = lenstest.DisplayPatch + ": a missing file or a directory is named through safe()"
	pendingPathCrash = lenstest.DisplayPatch + ": a name that is not UTF-8 holds a lone surrogate, which unpatched lens.py crashes printing"
)

// makeProbes creates, in dir, for each name variant: no file, a valid KNOBE
// file, a directory, a mode-000 file (unless running as root, who can read
// it), and a path through a regular file.
func makeProbes(t *testing.T, dir string) []pathProbe {
	valid, err := os.ReadFile(filepath.Join(lenstest.ProtocolDir(t), "test-vectors", "minimal-valid.knobe.md"))
	if err != nil {
		t.Fatal(err)
	}
	var probes []pathProbe
	for variant, part := range nameVariants {
		at := func(kind string) string { return filepath.Join(dir, kind+"-"+part+".knobe.md") }
		add := func(kind, path, pending string) {
			probes = append(probes, pathProbe{kind + "-" + variant, path, pending})
		}
		// lens.py shows a missing file or a directory by name; the pending
		// patch escapes it. "quote" needs no escaping.
		pending := map[string]string{"non-utf8": pendingPathCrash, "ansi": pendingPathSafe, "bidi": pendingPathSafe}[variant]
		add("missing", at("missing"), pending)
		if err := os.WriteFile(at("exists"), valid, 0o644); err != nil {
			t.Fatal(err)
		}
		add("exists", at("exists"), "")
		if err := os.Mkdir(at("dir"), 0o755); err != nil {
			t.Fatal(err)
		}
		add("dir", at("dir"), pending)
		// An OSError shows repr(path), which escapes the name already.
		add("notdir", filepath.Join(at("exists"), "x.knobe.md"), "")
		if os.Geteuid() != 0 {
			if err := os.WriteFile(at("noperm"), valid, 0o000); err != nil {
				t.Fatal(err)
			}
			add("noperm", at("noperm"), "")
		}
	}
	if os.Geteuid() == 0 {
		t.Log("running as root: mode-000 probes skipped (root can read them)")
	}
	return probes
}

func runCapture(args ...string) (string, int) {
	var out, errOut strings.Builder
	code := run(args, &out, &errOut)
	return out.String(), code
}

func TestPathProbesMatchLens(t *testing.T) {
	lenstest.RequirePython(t)
	lenstest.LogMode(t)
	probes := makeProbes(t, t.TempDir())
	for _, p := range probes {
		for _, mode := range []struct {
			args    []string
			pending string
		}{{[]string{"--json", p.path}, p.pending}, {[]string{p.path}, p.pending}} {
			want, wantExit := lenstest.Lens(t, mode.args...)
			got, gotExit := runCapture(mode.args...)
			label := p.name + " (human)"
			if len(mode.args) == 2 {
				label = p.name + " --json"
			}
			if !utf8.ValidString(got) {
				t.Errorf("%s: output is not valid UTF-8: %q", label, got)
			}
			if lenstest.Compare(t, label, want, got, lenstest.Expect{Pending: mode.pending}) && want == got && wantExit != gotExit {
				t.Errorf("%s: exit code %d, lens.py %d", label, gotExit, wantExit)
			}
		}
	}
	t.Logf("compared %d paths", len(probes))
}

func TestPathReasonsFollowSpec(t *testing.T) {
	dir := t.TempDir()
	if !utf8.ValidString(dir) || strings.ContainsAny(dir, "'\\\x1b") {
		t.Skipf("temp dir %q would need escaping itself", dir)
	}
	makeProbesNoLens(t, dir)
	reason := func(name string) string { return knobe.VerifyFile(filepath.Join(dir, name)).Reason }
	cases := map[string]string{
		"missing-\xff.knobe.md":           "file not found: " + dir + `/missing-\udcff.knobe.md`,
		"missing-\x1b[31m.knobe.md":       "file not found: " + dir + `/missing-\x1b[31m.knobe.md`,
		"missing-\u202e.knobe.md":         "file not found: " + dir + `/missing-\u202e.knobe.md`,
		"missing-\xed\xa0\x80.knobe.md":   "file not found: " + dir + `/missing-\udced\udca0\udc80.knobe.md`,
		"dir-\xff.knobe.md":               "path is a directory, not a file: " + dir + `/dir-\udcff.knobe.md`,
		"exists-\xff.knobe.md/x.knobe.md": "could not read file: [Errno 20] Not a directory: '" + dir + `/exists-\udcff.knobe.md/x.knobe.md'`,
		"exists-'q.knobe.md/x.knobe.md":   `could not read file: [Errno 20] Not a directory: "` + dir + `/exists-'q.knobe.md/x.knobe.md"`,
	}
	if os.Geteuid() != 0 {
		cases["noperm-\xff.knobe.md"] = "could not read file: [Errno 13] Permission denied: '" + dir + `/noperm-\udcff.knobe.md'`
		cases["noperm-\x1b[31m.knobe.md"] = "could not read file: [Errno 13] Permission denied: '" + dir + `/noperm-\x1b[31m.knobe.md'`
		cases["noperm-\u202e.knobe.md"] = "could not read file: [Errno 13] Permission denied: '" + dir + `/noperm-\u202e.knobe.md'`
	}
	for name, want := range cases {
		if got := reason(name); got != want {
			t.Errorf("%q:\n got %s\nwant %s", name, got, want)
		}
	}
	// Every report on these paths is valid UTF-8, in either form.
	for name := range cases {
		for _, args := range [][]string{{"--json", filepath.Join(dir, name)}, {filepath.Join(dir, name)}} {
			if out, code := runCapture(args...); !utf8.ValidString(out) || code != 2 {
				t.Errorf("%q %v: exit %d, output %q", name, args[0], code, out)
			}
		}
	}
}

// makeProbesNoLens creates the probe files without needing lens.py.
func makeProbesNoLens(t *testing.T, dir string) {
	for _, part := range nameVariants {
		if err := os.WriteFile(filepath.Join(dir, "exists-"+part+".knobe.md"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(dir, "dir-"+part+".knobe.md"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "noperm-"+part+".knobe.md"), []byte("x"), 0o000); err != nil {
			t.Fatal(err)
		}
	}
}
