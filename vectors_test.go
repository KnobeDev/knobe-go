package knobe

import (
	"path/filepath"
	"testing"
)

// The published test vectors and their expected results, transcribed from
// test-vectors/README.md, adversarial/README.md and interpretation/README.md.
// Reproducing the first nine is the bar for "canonically compatible with
// KNOBE Protocol v1". An empty body means the README leaves it open.
var expected = []struct {
	file, status, body, conformance string
}{
	// Core six + additional three (the conformance bar)
	{"minimal-valid.knobe.md", "verified", "", "valid"},
	{"full-valid.knobe.md", "verified", "", "valid"},
	{"body-modified.knobe.md", "verified-body-modified", "modified", "valid"},
	{"payload-modified.knobe.md", "failed", "", "valid"},
	{"unreadable.knobe.md", "unreadable", "", "invalid"},
	{"unicode-valid.knobe.md", "verified", "", "valid"},
	{"numeric-violation.knobe.md", "verified", "", "invalid"},
	{"omitted-body-hash.knobe.md", "verified", "omitted", "valid"},
	{"multi-block.knobe.md", "verified", "omitted", "warnings"},
	// Adversarial hardening set
	{"adversarial/bad-attribution-sources-type.knobe.md", "verified", "omitted", "invalid"},
	{"adversarial/bad-body-hash-format.knobe.md", "verified-body-modified", "modified", "invalid"},
	{"adversarial/bad-created-date.knobe.md", "verified", "omitted", "invalid"},
	{"adversarial/control-character-title.knobe.md", "verified", "omitted", "valid"},
	{"adversarial/duplicate-key.knobe.md", "unreadable", "", "invalid"},
	{"adversarial/multi-block-warning.knobe.md", "verified", "omitted", "warnings"},
	{"adversarial/nfc-key-collision.knobe.md", "unreadable", "", "invalid"},
	{"adversarial/no-frontmatter-valid-payload.knobe.md", "verified", "omitted", "invalid"},
	{"adversarial/payload-array.knobe.md", "unreadable", "", "invalid"},
	{"adversarial/unsupported-spec-version.knobe.md", "unreadable", "", "invalid"},
	// Interpretation set (ERRATA rulings)
	{"interpretation/astral-unicode-literal.knobe.md", "verified", "omitted", "valid"},
	{"interpretation/attribution-missing.knobe.md", "verified", "omitted", "invalid"},
	{"interpretation/base64-unpadded.knobe.md", "unreadable", "", "invalid"},
	{"interpretation/begin-marker-mid-line.knobe.md", "verified", "yes", "valid"},
	{"interpretation/boolean-null-values.knobe.md", "verified", "omitted", "valid"},
	{"interpretation/spec-version-frontmatter-mismatch.knobe.md", "verified", "omitted", "warnings"},
}

func TestPublishedVectors(t *testing.T) {
	dir := filepath.Join(protocolDir(t), "test-vectors")
	for _, want := range expected {
		t.Run(want.file, func(t *testing.T) {
			r := VerifyFile(filepath.Join(dir, want.file))
			if string(r.Status) != want.status || string(r.Conformance) != want.conformance ||
				(want.body != "" && string(r.BodyVerified) != want.body) {
				t.Errorf("want %s/%q/%s, got %s/%q/%s (%q)", want.status, want.body, want.conformance,
					r.Status, r.BodyVerified, r.Conformance, r.ConformanceIssues)
			}
			if r.Status == Unreadable && r.BodyVerified != "" {
				t.Errorf("unreadable file must omit body_verified, got %q", r.BodyVerified)
			}
		})
	}
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
