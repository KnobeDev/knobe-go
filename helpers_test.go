package knobe

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/KnobeDev/knobe-go/internal/lenstest"
)

// protocolDir is the KNOBE Protocol checkout holding lens.py and the test
// vectors. Override with KNOBE_PROTOCOL_DIR (default: ../knobe-protocol).
func protocolDir(t *testing.T) string {
	t.Helper()
	return lenstest.ProtocolDir(t)
}

// requirePython skips a differential test when python3 is unavailable.
func requirePython(t *testing.T) {
	t.Helper()
	lenstest.RequirePython(t)
}

// pythonVersion is python3's "major.minor".
var pythonVersion = lenstest.PythonVersion

// cpython313Only are hostile cases whose lens.py report depends on CPython
// 3.13's json.loads recursion limits (3.12 stops one level earlier). CI runs
// Python 3.13; elsewhere these cases are skipped, with a note.
var cpython313Only = map[string]bool{
	"deep-nesting-9997": true, "deep-nesting-9998": true, "deep-nesting-9998-then-dup-key": true,
	"deep-object-9995": true, "deep-object-9996": true, "deep-object-9996-dup-key": true,
	"deep-float-9995": true, "deep-float-9996": true, "deep-overflow-float-9996": true,
	"deep-nan-9995": true, "deep-nan-9996": true, "deep-int-9998": true,
}

func skipOnThisPython(t *testing.T, name string) bool {
	t.Helper()
	if cpython313Only[name] && pythonVersion() != "3.13" {
		t.Logf("%s: skipped, its limit is CPython 3.13's and python3 is %s", name, pythonVersion())
		return true
	}
	return false
}

// corpus is every published .knobe.md: test vectors (all sets), examples,
// and site copies.
func corpus(t *testing.T) []string {
	root := protocolDir(t)
	var out []string
	for _, sub := range []string{"test-vectors", "examples", "site"} {
		filepath.WalkDir(filepath.Join(root, sub), func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(p, ".knobe.md") {
				out = append(out, p)
			}
			return nil
		})
	}
	sort.Strings(out)
	if len(out) == 0 {
		t.Fatalf("no .knobe.md files under %s", root)
	}
	return out
}

// gate holds the fields the upstream parity harness (knobe-core.selftest.mjs)
// compares, each as compact canonical JSON so values of any type compare.
type gate struct {
	State, Conformance, BodyVerified, Computed, Stored, BlockCount, MultipleBlocks string
	ExitCode                                                                       int
}

func gateFromJSON(t *testing.T, stdout string, exit int) gate {
	t.Helper()
	res, err := ParseJSON(strings.TrimSpace(stdout))
	if err != nil {
		t.Fatalf("bad JSON (%v): %s", err, stdout)
	}
	get := func(k string) string {
		v, ok := res.Value.Get(k)
		if !ok {
			return "<absent>"
		}
		s, err := canonical(v)
		if err != nil {
			return "<non-finite>"
		}
		return s
	}
	return gate{
		State: get("state"), Conformance: get("conformance"), BodyVerified: get("body_verified"),
		Computed: get("computed"), Stored: get("stored"), BlockCount: get("block_count"),
		MultipleBlocks: get("multiple_blocks"), ExitCode: exit,
	}
}

// lens runs `python3 lens.py --json FILE`; ok is false if lens.py crashed.
func lens(t *testing.T, file string) (gate, bool) {
	t.Helper()
	cmd := exec.Command("python3", filepath.Join(protocolDir(t), "lens.py"), "--json", file)
	out, _ := cmd.Output()
	if strings.TrimSpace(string(out)) == "" {
		return gate{}, false
	}
	return gateFromJSON(t, string(out), cmd.ProcessState.ExitCode()), true
}

// ours runs this verifier through the same JSON surface.
func ours(t *testing.T, file string) gate {
	r := VerifyFile(file)
	return gateFromJSON(t, r.JSON(), r.ExitCode())
}
