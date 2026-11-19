package knobe

import (
	"os"
	"path"
	"path/filepath"
	"slices"
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
// relative to test-vectors/, with forward slashes. body is "—" for the
// omitted that unreadable files report.
type expectation struct {
	file, status, body, conformance string
}

// tableCells returns the cells of a Markdown table row, split on unescaped
// pipes, and false for a line that is not a table row.
func tableCells(line string) ([]string, bool) {
	row, ok := strings.CutPrefix(strings.TrimSpace(line), "|")
	if !ok {
		return nil, false
	}
	cells := []string{}
	start, escaped := 0, false
	for i, c := range row {
		switch {
		case escaped: // the character after a backslash is literal, `\|` included
			escaped = false
		case c == '\\':
			escaped = true
		case c == '|':
			cells = append(cells, strings.TrimSpace(row[start:i]))
			start = i + 1
		}
	}
	if last := strings.TrimSpace(row[start:]); last != "" {
		cells = append(cells, last) // a row without a closing pipe
	}
	return cells, true
}

// column is the index of the header cell name or "expected <name>", ignoring
// case, or -1.
func column(header []string, name string) int {
	for i, h := range header {
		if h = strings.ToLower(h); h == name || h == "expected "+name {
			return i
		}
	}
	return -1
}

// vectorName is the file a row's first cell names in backticks, if it is a
// .knobe.md file.
func vectorName(cell string) (string, bool) {
	name, ok := strings.CutPrefix(cell, "`")
	if !ok {
		return "", false
	}
	name, ok = strings.CutSuffix(name, "`")
	return name, ok && strings.HasSuffix(name, ".knobe.md")
}

// publishedExpected reads the expected results from the tables in
// test-vectors/README.md, adversarial/README.md and interpretation/README.md
// of the protocol checkout. Reading them, rather than a copy, means a vector
// published upstream is checked against its published result on the next run.
//
// The status, body_verified and conformance columns are found by their
// header, which every table has had since knobe-protocol PR #30 (merged as
// 02ad723). A table starts at its header row (a first cell of "file", or the
// first row after a non-table line) and ends at the next non-table line or
// header row.
func publishedExpected(t *testing.T) []expectation {
	t.Helper()
	root := filepath.Join(protocolDir(t), "test-vectors")
	var out []expectation
	for _, dir := range []string{"", "adversarial", "interpretation"} {
		readme := filepath.Join(dir, "README.md")
		data, err := os.ReadFile(filepath.Join(root, readme))
		if err != nil {
			t.Fatalf("expected results: %v", err)
		}
		var header []string
		inTable := false
		for _, line := range strings.Split(string(data), "\n") {
			cells, ok := tableCells(line)
			if !ok {
				inTable = false
				continue
			}
			if !inTable || (len(cells) > 0 && strings.EqualFold(cells[0], "file")) {
				header, inTable = cells, true
				continue
			}
			if len(cells) == 0 {
				continue
			}
			file, ok := vectorName(cells[0])
			if !ok {
				continue // the separator row, or a row that names no vector
			}
			if len(cells) != len(header) {
				t.Fatalf("%s: row has %d cells, header %d: %q", readme, len(cells), len(header), line)
			}
			at := func(name string) string {
				i := column(header, name)
				if i < 0 {
					t.Fatalf("%s: the table listing %s has no %s column (upstream added body_verified "+
						"to every table in PR #30; use a checkout at 02ad723 or later)", readme, file, name)
				}
				// "verified (last block)" and "valid (where readable)" keep the first word.
				f := strings.Fields(cells[i])
				if len(f) == 0 {
					t.Fatalf("%s: blank %s cell in the row %q", readme, name, line)
				}
				return f[0]
			}
			out = append(out, expectation{
				file:        path.Join(dir, file),
				status:      at("status"),
				body:        at("body_verified"),
				conformance: at("conformance"),
			})
		}
	}
	return out
}

func TestTableCells(t *testing.T) {
	for _, tc := range []struct {
		line string
		want []string
	}{
		{"| `a.knobe.md` | verified | — | invalid |", []string{"`a.knobe.md`", "verified", "—", "invalid"}},
		{"  | file | expected status |  ", []string{"file", "expected status"}},
		{`| x | a \| b | c`, []string{"x", `a \| b`, "c"}},
		{"|---|---|", []string{"---", "---"}},
	} {
		if got, ok := tableCells(tc.line); !ok || !slices.Equal(got, tc.want) {
			t.Errorf("tableCells(%q) = %q, %v; want %q", tc.line, got, ok, tc.want)
		}
	}
	if _, ok := tableCells("not a table | row"); ok {
		t.Error("a line that does not start with a pipe is not a table row")
	}
	header := []string{"file", "Expected Status", "body_verified", "notes"}
	if column(header, "status") != 1 || column(header, "body_verified") != 2 || column(header, "conformance") != -1 {
		t.Errorf("column lookup in %q", header)
	}
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
			bodyOK := body == want.body
			if want.body == "—" {
				bodyOK = body == ""
			}
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
