package knobe

import (
	"fmt"
	"io"
	"strconv"
)

// JSON renders the report exactly as `python3 lens.py --json` does: the same
// keys in the same order, two-space indent, literal UTF-8.
func (r Report) JSON() string {
	str := func(s string) Value { return Value{Kind: String, S: s} }
	orNull := func(s string) Value {
		if s == "" {
			return Value{Kind: Null}
		}
		return str(s)
	}
	stored := Value{Kind: Null}
	if r.Stored != nil {
		stored = *r.Stored
	}
	issues := make([]Value, len(r.ConformanceIssues))
	for i, s := range r.ConformanceIssues {
		issues[i] = str(s)
	}
	doc := Value{Kind: Object, Obj: []Member{
		{"state", str(string(r.Status))},
		{"computed", orNull(r.Computed)},
		{"stored", stored},
		{"body_verified", orNull(string(r.BodyVerified))},
		{"conformance", str(string(r.Conformance))},
		{"conformance_issues", Value{Kind: Array, Arr: issues}},
		{"multiple_blocks", Value{Kind: Bool, B: r.MultipleBlocks()}},
		{"block_count", Value{Kind: Int, Num: strconv.Itoa(r.BlockCount)}},
		{"block_used", Value{Kind: Int, Num: strconv.Itoa(r.BlockUsed())}},
		{"reason", orNull(r.Reason)},
	}}
	return prettyJSON(doc)
}

// WriteHuman writes the human-readable report in lens.py's layout. Every
// payload-derived string is escaped first, so control characters and
// terminal escape sequences in a hostile file are shown, never executed.
func (r Report) WriteHuman(w io.Writer) {
	line := func(label, value string) { fmt.Fprintf(w, "%-19s%s\n", label+":", value) }
	issues := func() {
		for _, issue := range r.ConformanceIssues {
			fmt.Fprintf(w, "  - %s\n", SafeString(issue, 0))
		}
	}
	if r.Status == Unreadable {
		line("status", "unreadable ("+SafeString(r.Reason, 300)+")")
		line("conformance", string(r.Conformance))
		issues()
		return
	}
	field := func(k string) string {
		v, ok := r.Payload.Get(k)
		if !ok {
			return "None"
		}
		return safe(v)
	}
	line("title", field("title"))
	line("spec_version", field("spec_version"))
	line("quarantine_status", field("quarantine_status"))
	line("privacy_level", field("privacy_level"))
	line("computed_hash", r.Computed)
	stored := repr(*r.Stored)
	if s, ok := r.Stored.Str(); ok {
		stored = SafeString(s, 0) // lens.py prints str(stored) whole; we escape it
	}
	line("stored_hash", stored)
	line("status", string(r.Status))
	if r.MultipleBlocks() {
		line("WARNING", fmt.Sprintf("multiple payload blocks present. Evaluated block %d of %d per spec §3.3.",
			r.BlockUsed(), r.BlockCount))
	}
	line("body_verified", string(r.BodyVerified))
	line("conformance", string(r.Conformance))
	issues()
	if r.Status == Verified || r.Status == VerifiedBodyModified {
		fmt.Fprintln(w, "note: integrity verified. Integrity is not truth — inspect before trusting.")
	}
	if r.Status == VerifiedBodyModified {
		fmt.Fprintln(w, "note: the markdown body differs from the sealed body. Inspect before relying on this version.")
	}
}
