package knobe

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// protocolDir is the KNOBE Protocol checkout holding lens.py and the test
// vectors. Override with KNOBE_PROTOCOL_DIR (default: ../knobe-protocol).
func protocolDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("KNOBE_PROTOCOL_DIR")
	if dir == "" {
		dir = filepath.Join("..", "knobe-protocol")
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

// requirePython skips a differential test when python3 is unavailable.
func requirePython(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not found; differential tests against lens.py skipped")
	}
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
