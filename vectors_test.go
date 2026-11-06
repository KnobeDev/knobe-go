package knobe

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// coreNine is the conformance bar: reproducing these nine is what makes a
// verifier "canonically compatible with KNOBE Protocol v1".
var coreNine = []string{
	"minimal-valid.knobe.md", "full-valid.knobe.md", "body-modified.knobe.md",
	"payload-modified.knobe.md", "unreadable.knobe.md", "unicode-valid.knobe.md",
	"numeric-violation.knobe.md", "omitted-body-hash.knobe.md", "multi-block.knobe.md",
}

// expectation is one row of a published expected-results table. file is
// relative to test-vectors/, with forward slashes. body is "" where the table
// has no body_verified column (the core nine) and "—" for the omitted that
// unreadable files report.
type expectation struct {
	file, status, body, conformance string
}

var tableRow = regexp.MustCompile("^\\|\\s*`([^`]+\\.knobe\\.md)`\\s*\\|(.*)$")

// publishedExpected reads the expected results from the tables in
// test-vectors/README.md, adversarial/README.md and interpretation/README.md
// of the protocol checkout. Reading them, rather than a copy, means a vector
// published upstream is checked against its published result on the next run.
func publishedExpected(t *testing.T) []expectation {
	t.Helper()
	root := filepath.Join(protocolDir(t), "test-vectors")
	var out []expectation
	for _, set := range []struct {
		dir     string
		hasBody bool
	}{{"", false}, {"adversarial", true}, {"interpretation", true}} {
		data, err := os.ReadFile(filepath.Join(root, set.dir, "README.md"))
		if err != nil {
			t.Fatalf("expected results: %v", err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			m := tableRow.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			// "verified (last block)" and "valid (where readable)" keep the first word.
			var cells []string
			for _, c := range strings.Split(m[2], "|") {
				if f := strings.Fields(c); len(f) > 0 {
					cells = append(cells, f[0])
				} else {
					cells = append(cells, "")
				}
			}
			e := expectation{file: path.Join(set.dir, m[1])}
			switch {
			case set.hasBody && len(cells) >= 3:
				e.status, e.body, e.conformance = cells[0], cells[1], cells[2]
			case !set.hasBody && len(cells) >= 2:
				e.status, e.conformance = cells[0], cells[1]
			default:
				t.Fatalf("%s: cannot read the expected-results row %q", filepath.Join(set.dir, "README.md"), line)
			}
			if e.status == "" || e.conformance == "" || (set.hasBody && e.body == "") {
				t.Fatalf("%s: blank cell in the expected-results row %q", filepath.Join(set.dir, "README.md"), line)
			}
			out = append(out, e)
		}
	}
	return out
}

func TestPublishedVectors(t *testing.T) {
	dir := filepath.Join(protocolDir(t), "test-vectors")
	rows := publishedExpected(t)
	listed := map[string]bool{}
	for _, want := range rows {
		listed[want.file] = true
		t.Run(want.file, func(t *testing.T) {
			p := filepath.Join(dir, filepath.FromSlash(want.file))
			if _, err := os.Stat(p); err != nil {
				t.Fatalf("listed in the README but missing: %v", err)
			}
			r := VerifyFile(p)
			body := string(r.BodyVerified)
			bodyOK := want.body == "" || body == want.body || (want.body == "—" && body == "")
			if string(r.Status) != want.status || string(r.Conformance) != want.conformance || !bodyOK {
				t.Errorf("want %s/%q/%s, got %s/%q/%s (%q)", want.status, want.body, want.conformance,
					r.Status, r.BodyVerified, r.Conformance, r.ConformanceIssues)
			}
			if r.Status == Unreadable && r.BodyVerified != "" {
				t.Errorf("unreadable file must omit body_verified, got %q", r.BodyVerified)
			}
		})
	}
	for _, f := range coreNine {
		if !listed[f] {
			t.Errorf("the README tables do not list the core vector %s", f)
		}
	}
	// Every published vector must have a published expected result.
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			t.Errorf("cannot list %s: %v", p, err)
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(p, ".knobe.md") {
			rel, _ := filepath.Rel(dir, p)
			if !listed[filepath.ToSlash(rel)] {
				t.Errorf("%s has no expected result in the test-vectors READMEs", filepath.ToSlash(rel))
			}
		}
		return nil
	})
}

func TestVectorExitCodes(t *testing.T) {
	dir := filepath.Join(protocolDir(t), "test-vectors")
	for file, code := range map[string]int{
		"unreadable.knobe.md":        2,
		"minimal-valid.knobe.md":     0,
		"multi-block.knobe.md":       0,
		"numeric-violation.knobe.md": 1,
		"payload-modified.knobe.md":  1,
	} {
		if got := VerifyFile(filepath.Join(dir, file)).ExitCode(); got != code {
			t.Errorf("%s: exit %d, want %d", file, got, code)
		}
	}
}

func TestErrataMessages(t *testing.T) {
	dir := filepath.Join(protocolDir(t), "test-vectors", "interpretation")
	r := VerifyFile(filepath.Join(dir, "spec-version-frontmatter-mismatch.knobe.md"))
	want := "frontmatter spec_version '1.1' does not match sealed payload spec_version '1.0'"
	if len(r.ConformanceIssues) != 1 || r.ConformanceIssues[0] != want {
		t.Errorf("E5 issue text: got %q", r.ConformanceIssues)
	}
	r = VerifyFile(filepath.Join(dir, "attribution-missing.knobe.md"))
	if len(r.ConformanceIssues) != 1 || r.ConformanceIssues[0] != "required field missing: attribution" {
		t.Errorf("E9 issues: got %q", r.ConformanceIssues)
	}
}

func TestMissingFileIsUnreadable(t *testing.T) {
	r := VerifyFile("/definitely/not/here.knobe.md")
	if r.Status != Unreadable || r.ExitCode() != 2 {
		t.Errorf("got %s exit %d", r.Status, r.ExitCode())
	}
}
