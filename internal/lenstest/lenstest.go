// Package lenstest holds what the differential tests share: where the KNOBE
// Protocol checkout is, how to run its lens.py, and whether that lens.py
// already carries the display patch that is pending upstream.
package lenstest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ProtocolDir is the KNOBE Protocol checkout holding lens.py and the test
// vectors. Override with KNOBE_PROTOCOL_DIR (default: knobe-protocol next
// to this module's root).
func ProtocolDir(t testing.TB) string {
	t.Helper()
	dir := os.Getenv("KNOBE_PROTOCOL_DIR")
	if dir == "" {
		dir = filepath.Join(moduleRoot(t), "..", "knobe-protocol")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(abs, "lens.py")); err != nil {
		t.Fatalf("KNOBE protocol checkout not found at %s (set KNOBE_PROTOCOL_DIR)", abs)
	}
	return abs
}

func moduleRoot(t testing.TB) string {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

// RequirePython skips a differential test when python3 is unavailable.
func RequirePython(t testing.TB) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not found; differential tests against lens.py skipped")
	}
}

// PythonVersion is python3's "major.minor".
var PythonVersion = sync.OnceValue(func() string {
	out, err := exec.Command("python3", "-c", "import sys; print('%d.%d' % sys.version_info[:2])").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
})

// Lens runs `python3 lens.py args...` and returns its stdout and exit code.
// A crash gives whatever was printed before it (usually nothing).
func Lens(t testing.TB, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("python3", append([]string{filepath.Join(ProtocolDir(t), "lens.py")}, args...)...)
	out, _ := cmd.Output()
	return string(out), cmd.ProcessState.ExitCode()
}

// DisplayPatch names the upstream patch series knobe-go's display rules
// follow: lens.py and knobe-core.js commits in KnobeOne/knobe-protocol that
// make safe() escape bidi controls, line separators and unpaired surrogates,
// show command-line paths through safe(), and escape every printed issue
// and stored_hash. Until upstream merges it, lens.py on main prints those
// raw (or crashes printing a surrogate), so the cases that exercise them
// cannot match there.
const DisplayPatch = "upstream patch 3-display-escaping"

var patched struct {
	once sync.Once
	dir  string
	yes  bool
	err  error
}

// DisplayPatched reports whether the lens.py under test has DisplayPatch,
// by importing it and checking safe() on a bidi override and a lone
// surrogate.
func DisplayPatched(t testing.TB) bool {
	t.Helper()
	dir := ProtocolDir(t)
	patched.once.Do(func() {
		patched.dir = dir
		code := "import sys; sys.path.insert(0, sys.argv[1]); import lens; " +
			`print(lens.safe('\u202e\ud800') == '\\u202e\\ud800')`
		out, err := exec.Command("python3", "-c", code, dir).Output()
		patched.yes, patched.err = strings.TrimSpace(string(out)) == "True", err
	})
	if patched.err != nil {
		t.Fatalf("could not import lens.py from %s to check for %s: %v", dir, DisplayPatch, patched.err)
	}
	if patched.dir != dir {
		t.Fatalf("KNOBE_PROTOCOL_DIR changed during the run (%s, then %s)", patched.dir, dir)
	}
	return patched.yes
}

// LogMode logs which comparison mode the test runs in.
func LogMode(t testing.TB) {
	t.Helper()
	if DisplayPatched(t) {
		t.Logf("mode: lens.py has %s; every case must match byte for byte", DisplayPatch)
	} else {
		t.Logf("mode: lens.py predates %s; cases listed as pending must differ, all others must match", DisplayPatch)
	}
}

// Expect says how one output must compare with lens.py's.
type Expect struct {
	// ByDesign, when set, is why this output always differs from lens.py.
	ByDesign string
	// Pending, when set, is why this output differs from a lens.py without
	// DisplayPatch (which may crash: empty output counts as differing).
	Pending string
}

// Compare checks got against lens.py's want under e. It returns false, after
// reporting, when the outputs do not compare as required.
func Compare(t testing.TB, name, want, got string, e Expect) bool {
	t.Helper()
	mustDiffer, why := false, ""
	switch {
	case e.ByDesign != "":
		mustDiffer, why = true, "listed as differing by design: "+e.ByDesign
	case e.Pending != "" && !DisplayPatched(t):
		mustDiffer, why = true, "listed as pending upstream: "+e.Pending
	}
	if (want == got) == mustDiffer {
		state := "differs"
		if want == got {
			state = "matches although " + why
		}
		t.Errorf("%s %s\n--- lens.py\n%s\n--- ours\n%s", name, state, want, got)
		return false
	}
	return true
}
