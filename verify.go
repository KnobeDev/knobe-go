package knobe

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"unicode/utf8"
)

// The verifier follows lens.py verify(). It reports three independent
// dimensions: status (integrity), body_verified, and conformance.

const (
	BeginMarker = "-----BEGIN KNOBE B64-----"
	EndMarker   = "-----END KNOBE B64-----"
)

// supportedSpecVersions are the spec_version values this verifier implements.
var supportedSpecVersions = []string{"1.0"}

var requiredFields = []string{
	"spec_version", "title", "summary", "content_type", "created_date",
	"license", "privacy_level", "quarantine_status", "attribution", "payload_hash",
}

// Status is the integrity result (spec §7).
type Status string

const (
	Verified             Status = "verified"
	VerifiedBodyModified Status = "verified-body-modified"
	Failed               Status = "failed"
	Unreadable           Status = "unreadable"
)

// Conformance is the schema/spec compliance result (spec §7).
type Conformance string

const (
	Valid    Conformance = "valid"
	Warnings Conformance = "warnings"
	Invalid  Conformance = "invalid"
)

// BodyVerified is the optional body-hash result (spec §6, §7).
type BodyVerified string

const (
	BodyYes      BodyVerified = "yes"
	BodyModified BodyVerified = "modified"
	BodyOmitted  BodyVerified = "omitted"
)

// Report is a verification result with lens.py's fields and semantics.
type Report struct {
	Status Status
	// Computed is the recomputed payload hash; empty when unreadable.
	Computed string
	// Stored is the payload_hash member as found (any JSON type; the empty
	// string if absent). Nil when unreadable.
	Stored *Value
	// Payload is the decoded payload, when one was decoded.
	Payload *Value
	// BodyVerified is empty when unreadable (machine output then says null).
	BodyVerified      BodyVerified
	Conformance       Conformance
	ConformanceIssues []string
	// BlockCount is the number of payload blocks found; the last is evaluated.
	BlockCount int
	// Reason says why the file is unreadable; empty otherwise.
	Reason string
}

func unreadable(reason string, blocks int, payload *Value) Report {
	return Report{
		Status:            Unreadable,
		Payload:           payload,
		Conformance:       Invalid,
		ConformanceIssues: []string{reason},
		BlockCount:        blocks,
		Reason:            reason,
	}
}

// MultipleBlocks reports whether more than one payload block was present.
func (r Report) MultipleBlocks() bool { return r.BlockCount > 1 }

// BlockUsed is the 1-based index of the evaluated block: always the last (spec §3.3).
func (r Report) BlockUsed() int { return r.BlockCount }

// ExitCode is lens.py's: 0 when integrity holds and conformance is valid or
// warnings; 1 when the payload failed or conformance is invalid; 2 when
// the file is unreadable.
func (r Report) ExitCode() int {
	switch {
	case r.Status == Unreadable:
		return 2
	case (r.Status == Verified || r.Status == VerifiedBodyModified) && r.Conformance != Invalid:
		return 0
	}
	return 1
}

// MaxFileSize bounds what VerifyFile reads. Verifying an ordinary file costs
// about 25 bytes of memory per input byte, and a crafted file of many deeply
// nested arrays far more (about 9 GB at this limit), so an unbounded hostile
// file could exhaust a constrained host. Larger files are reported unreadable.
const MaxFileSize = 64 << 20

// VerifyFile reads and verifies a .knobe.md file of at most MaxFileSize
// bytes. It never panics on file contents; read errors are reported as
// unreadable.
func VerifyFile(path string) Report {
	data, err := readLimited(path)
	if errors.Is(err, errTooLarge) {
		return unreadable(fmt.Sprintf("file exceeds the %d MiB size limit: %s", MaxFileSize>>20, path), 0, nil)
	}
	if err != nil {
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return unreadable("file not found: "+path, 0, nil)
		case errors.Is(err, syscall.EISDIR):
			return unreadable("path is a directory, not a file: "+path, 0, nil)
		}
		return unreadable(fmt.Sprintf("could not read file: %v", err), 0, nil)
	}
	return VerifyBytes(data)
}

var errTooLarge = errors.New("file too large")

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileSize {
		return nil, errTooLarge
	}
	return data, nil
}

// VerifyBytes verifies the contents of a .knobe.md file. Callers passing
// untrusted input should bound its size, as VerifyFile does.
func VerifyBytes(data []byte) Report {
	if !utf8.Valid(data) {
		return unreadable("file is not valid UTF-8", 0, nil)
	}
	return verifyText(string(data))
}

func verifyText(raw string) Report {
	blocks := findBlocks(raw)
	n := len(blocks)
	if n == 0 {
		return unreadable("no payload block found", 0, nil)
	}
	payload, rej := decodePayload(blocks[n-1])
	if rej == nil {
		rej = admit(payload.Value)
	}
	if rej != nil {
		count := n
		if rej.noBlocks {
			count = 0
		}
		r := unreadable(rej.reason, count, rej.payload)
		if rej.issue != "" {
			r.ConformanceIssues = []string{rej.issue}
		}
		return r
	}
	p := payload.Value

	// Canonical hash (spec §5). The parser rejects non-finite numbers, so
	// this fails only for a hand-built Value; kept as a guard.
	computed, err := PayloadHash(p)
	if err != nil {
		return unreadable("payload contains a number that cannot be canonicalized "+
			"(overflows to infinity); rejected", n, &p)
	}
	stored, ok := p.Get("payload_hash")
	if !ok {
		stored = Value{Kind: String}
	}
	missing := missingFields(p)
	status := Failed
	if s, ok := stored.Str(); ok && s == computed {
		status = Verified
	}
	fm := parseFrontmatter(raw)

	// body_verified is omitted for multiple blocks (ambiguous extraction),
	// no body_hash, or a payload that did not verify (untrusted).
	body := BodyOmitted
	if status == Verified && p.Has("body_hash") && n == 1 {
		match, found := bodyMatches(raw, p)
		if !found {
			return unreadable("body_hash present but YAML frontmatter delimiters not found", n, &p)
		}
		if match {
			body = BodyYes
		} else {
			body, status = BodyModified, VerifiedBodyModified
		}
	}

	level, issues := checkConformance(p, missing, fm, n)
	return Report{
		Status:            status,
		Computed:          computed,
		Stored:            &stored,
		Payload:           &p,
		BodyVerified:      body,
		Conformance:       level,
		ConformanceIssues: issues,
		BlockCount:        n,
	}
}

// rejection says why a payload makes the file unreadable.
type rejection struct {
	reason  string
	payload *Value // kept on the report where lens.py keeps it
	issue   string // replacement conformance issue, when it differs from reason
	// noBlocks reports a block count of 0, as lens.py does when verify()
	// raises and its command line builds the report without the blocks.
	noBlocks bool
}

func decodePayload(block string) (ParseResult, *rejection) {
	bytes, ok := decodeBlock(block)
	if !ok || !utf8.Valid(bytes) {
		return ParseResult{}, &rejection{reason: "payload could not be decoded or parsed"}
	}
	res, err := ParseJSON(string(bytes))
	if err == nil {
		return res, nil
	}
	var pe *ParseError
	if !errors.As(err, &pe) {
		return res, &rejection{reason: "payload could not be decoded or parsed"}
	}
	switch {
	case pe.IsDuplicate:
		return res, &rejection{reason: "payload contains duplicate JSON key: " +
			SafeString(pe.DuplicateKey, 300) + " (ambiguous; rejected)"}
	case pe.NonJSONConst:
		return res, &rejection{reason: "payload contains a non-JSON numeric constant (NaN/Infinity); rejected"}
	}
	return res, &rejection{reason: "payload could not be decoded or parsed"}
}

// admit applies the structural gates before hashing, in lens.py's order: a
// JSON object, no unpaired surrogate (within the nesting lens.py can walk),
// no NFC key collisions, and a spec_version this verifier implements.
func admit(p Value) *rejection {
	if p.Kind != Object {
		return &rejection{reason: "payload is not a JSON object (got " + typeName(p) + ")"}
	}
	switch scanPayload(p) {
	case scanTooDeep:
		return &rejection{reason: "verifier error (RecursionError); rejected", noBlocks: true}
	case scanLoneSurrogate:
		return &rejection{reason: "payload contains characters that cannot be UTF-8 encoded " +
			"(e.g. an unpaired surrogate); rejected"}
	}
	if c := nfcCollisions(p, ""); len(c) > 0 {
		if len(c) > 5 {
			c = c[:5]
		}
		return &rejection{reason: "payload keys collide under NFC normalization: " + strings.Join(c, "; ")}
	}
	// An unsupported spec_version cannot be honestly verified.
	if sv, ok := p.Get("spec_version"); ok && sv.Kind != Null {
		if s, isStr := sv.Str(); !isStr || !contains(supportedSpecVersions, s) {
			shown := SafeString(pyStr(sv), 300) // lens.py: safe(str(sv))
			return &rejection{
				reason:  "unsupported spec_version: " + shown,
				issue:   "unsupported spec_version: " + shown + " (this verifier supports ['1.0'])",
				payload: &p,
			}
		}
	}
	return nil
}

// maxScanLevel is the deepest nesting lens.py's _has_lone_surrogate can walk.
// It recurses through a generator, so each level costs two CPython frames;
// with the default recursion limit of 1000 and two frames already in use
// (the script and verify()), a value or object key nested 499 levels below
// the payload raises RecursionError.
const maxScanLevel = 498

type scanResult int

const (
	scanClean scanResult = iota
	scanLoneSurrogate
	scanTooDeep
)

// scanPayload follows lens.py _has_lone_surrogate: depth first in document
// order, each object key before its value, stopping at the first string
// holding an unpaired surrogate or at the first value too deep for CPython
// to reach, whichever comes first.
func scanPayload(p Value) scanResult { return scanValue(p, 0) }

func scanValue(v Value, level int) scanResult {
	if level > maxScanLevel {
		return scanTooDeep
	}
	switch v.Kind {
	case String:
		// The parser keeps an unpaired surrogate as WTF-8, the only invalid
		// UTF-8 a parsed string can hold.
		if !utf8.ValidString(v.S) {
			return scanLoneSurrogate
		}
	case Array:
		for _, item := range v.Arr {
			if r := scanValue(item, level+1); r != scanClean {
				return r
			}
		}
	case Object:
		for _, m := range v.Obj {
			if r := scanValue(Value{Kind: String, S: m.Key}, level+1); r != scanClean {
				return r
			}
			if r := scanValue(m.Val, level+1); r != scanClean {
				return r
			}
		}
	}
	return scanClean
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// missingFields lists absent required fields, plus attribution.sources when
// attribution is present without a truthy sources value.
func missingFields(p Value) []string {
	var missing []string
	for _, f := range requiredFields {
		if !p.Has(f) {
			missing = append(missing, f)
		}
	}
	if att, ok := p.Get("attribution"); ok {
		src, hasSrc := att.Get("sources")
		if att.Kind != Object || !hasSrc || !truthy(src) {
			missing = append(missing, "attribution.sources")
		}
	}
	return missing
}

// bodyMatches reports whether the body between the frontmatter and the
// single BEGIN marker matches body_hash. found is false when the
// frontmatter delimiters cannot be located.
func bodyMatches(raw string, p Value) (match, found bool) {
	marker := "\n" + BeginMarker + "\n"
	pre := ""
	if pos := strings.LastIndex(raw, marker); pos >= 0 {
		pre = raw[:pos]
	}
	start, ok := findBodyStart(pre)
	if !ok {
		return false, false
	}
	want, _ := p.Get("body_hash")
	s, isStr := want.Str()
	return isStr && s == BodyHash(pre[start:]), true
}

// findBlocks returns every payload block, as lens.py's
// re.findall(r'(?:^|\n)-----BEGIN KNOBE B64-----\n(.*?)\n-----END KNOBE B64-----', raw, re.DOTALL).
// Markers are line-anchored (ERRATA E2).
func findBlocks(raw string) []string {
	begin := BeginMarker + "\n"
	beginAfterNL := "\n" + begin
	end := "\n" + EndMarker
	var out []string
	pos := 0
	for pos <= len(raw) {
		var contentStart int
		if pos == 0 && strings.HasPrefix(raw, begin) {
			contentStart = len(begin)
		} else {
			nl := strings.Index(raw[pos:], beginAfterNL)
			if nl < 0 {
				break
			}
			contentStart = pos + nl + 1 + len(begin)
		}
		// Lazy (.*?): the first END after the content start.
		rel := strings.Index(raw[contentStart:], end)
		if rel < 0 {
			break
		}
		out = append(out, raw[contentStart:contentStart+rel])
		pos = contentStart + rel + len(end)
	}
	return out
}

// frontmatter holds what the conformance check needs from the YAML frontmatter.
type frontmatter struct {
	ok      bool
	spec    string
	hasSpec bool
	reason  string
}

// parseFrontmatter follows lens.py parse_frontmatter: the first line is
// exactly '---' (trailing CRs ignored) and a later line is exactly '---'.
// It captures the first spec_version value seen before the closing line.
func parseFrontmatter(raw string) frontmatter {
	raw = strings.TrimPrefix(raw, "\uFEFF")
	lines := strings.Split(raw, "\n")
	if strings.TrimRight(lines[0], "\r") != "---" {
		return frontmatter{reason: "missing opening '---' frontmatter delimiter"}
	}
	var fm frontmatter
	for _, line := range lines[1:] {
		line = strings.TrimRight(line, "\r")
		if line == "---" {
			fm.ok = true
			return fm
		}
		if !fm.hasSpec {
			fm.spec, fm.hasSpec = specVersionLine(line)
		}
	}
	fm.reason = "missing closing '---' frontmatter delimiter"
	return fm
}

// specVersionLine is re.match(r'\s*spec_version\s*:\s*(.+?)\s*$', line)
// followed by .strip() and stripping the quote characters " and ', with
// Python's Unicode \s.
func specVersionLine(line string) (string, bool) {
	rest, ok := strings.CutPrefix(strings.TrimLeftFunc(line, isPySpace), "spec_version")
	if !ok {
		return "", false
	}
	rest, ok = strings.CutPrefix(strings.TrimLeftFunc(rest, isPySpace), ":")
	if !ok || rest == "" {
		return "", false // (.+?) needs at least one character
	}
	// An all-whitespace value still matches (the group takes one whitespace
	// character), and strips to "".
	return strings.Trim(pyStrip(rest), `"'`), true
}

// findBodyStart follows lens.py _find_body_start: the offset just after the
// closing '---' line. ok is false when pre does not open with a '---' line
// (a BOM is not skipped here).
func findBodyStart(pre string) (int, bool) {
	if !strings.HasPrefix(pre, "---\n") && !strings.HasPrefix(pre, "---\r\n") {
		return 0, false
	}
	idx := strings.IndexByte(pre, '\n') + 1
	for {
		nl := strings.IndexByte(pre[idx:], '\n')
		line := pre[idx:]
		if nl >= 0 {
			line = pre[idx : idx+nl]
		}
		if strings.TrimRight(line, "\r") == "---" {
			if nl < 0 {
				return len(pre), true
			}
			return idx + nl + 1, true
		}
		if nl < 0 {
			return 0, false
		}
		idx += nl + 1
	}
}

// nfcCollisions lists keys that collapse to the same key under NFC; such a
// payload has no unambiguous canonical form.
func nfcCollisions(v Value, path string) []string {
	join := func(k string) string {
		if path == "" {
			return k
		}
		return path + "." + k
	}
	var out []string
	switch v.Kind {
	case Object:
		first := make(map[string]string, len(v.Obj)) // NFC form -> first original key
		for _, m := range v.Obj {
			nk := nfc(m.Key)
			if orig, seen := first[nk]; seen {
				out = append(out, reprStr(join(m.Key))+" collides with "+reprStr(orig)+" under NFC")
			} else {
				first[nk] = m.Key
			}
		}
		for _, m := range v.Obj {
			out = append(out, nfcCollisions(m.Val, join(m.Key))...)
		}
	case Array:
		for i, item := range v.Arr {
			out = append(out, nfcCollisions(item, fmt.Sprintf("%s[%d]", path, i))...)
		}
	}
	return out
}
