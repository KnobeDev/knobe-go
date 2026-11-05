package knobe

import (
	"bytes"
	"errors"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestParseRejectsAmbiguousAndIllegalJSON(t *testing.T) {
	var pe *ParseError
	_, err := ParseJSON(`{"a":1,"b":{"c":1,"c":2}}`)
	if !errors.As(err, &pe) || !pe.IsDuplicate || pe.DuplicateKey != "c" {
		t.Errorf("nested duplicate key: %v", err)
	}
	// A float lexeme that overflows to infinity is rejected like NaN, as
	// lens.py's parse_float hook does (upstream PR #11).
	for _, in := range []string{"[NaN]", "-Infinity", "Infinity", "1e400", "-1e400", "[1.5e309]", `{"payload_hash":1E999}`} {
		if _, err := ParseJSON(in); !errors.As(err, &pe) || !pe.NonJSONConst {
			t.Errorf("%s: want NonJSONConst, got %v", in, err)
		}
	}
	// Python raises the duplicate-key error only when the object closes
	// (object_pairs_hook), so any error later in that object comes first.
	for in, want := range map[string]string{
		`{"a":1,"a":1e400}`:           "nonconst",
		`{"a":1,"a":NaN}`:             "nonconst",
		`{"a":1,"a":2,}`:              "syntax",
		`{"a":{"b":1,"b":2},"a":3}`:   "dup b",
		`{"a":1,"a":2,"b":3,"b":4}`:   "dup a",
		`[{"a":1,"a":2},{"b":1,"b"}]`: "dup a",
	} {
		_, err := ParseJSON(in)
		got := "syntax"
		if errors.As(err, &pe) && pe.NonJSONConst {
			got = "nonconst"
		} else if errors.As(err, &pe) && pe.IsDuplicate {
			got = "dup " + pe.DuplicateKey
		}
		if err == nil || got != want {
			t.Errorf("%s: want %s, got %s (%v)", in, want, got, err)
		}
	}
	for _, in := range []string{"[1,]", "01", "1.", ".5", "-", "\uFEFF{}", "\"a\x01\"", `"\x"`, `"\u12"`,
		strings.Repeat("[", 10000), "{} x", `{"a" 1}`, "tru", "1e", `"unterminated`, strings.Repeat("9", 4301)} {
		if _, err := ParseJSON(in); err == nil {
			t.Errorf("%q: want error", in)
		}
	}
}

func TestParseKeepsBigIntsAndPairsSurrogates(t *testing.T) {
	res, err := ParseJSON("123456789012345678901234567890")
	if err != nil || res.Value.Kind != Int || res.Value.Num != "123456789012345678901234567890" {
		t.Errorf("big int: %+v %v", res, err)
	}
	res, _ = ParseJSON(`"\ud83d\ude00"`)
	if res.Value.S != "\U0001F600" || res.LoneSurrogate {
		t.Errorf("surrogate pair: %+v", res)
	}
	for _, in := range []string{`"\ud800"`, `"\udc00\ud800"`, `"\ud800\u0041"`} {
		res, err := ParseJSON(in)
		if err != nil || !res.LoneSurrogate {
			t.Errorf("%s: want parsed with LoneSurrogate, got %+v %v", in, res, err)
		}
	}
	res, _ = ParseJSON(`"\ud800\u0041"`)
	if !strings.HasSuffix(res.Value.S, "A") {
		t.Errorf("escape after lone high surrogate is decoded on its own: %q", res.Value.S)
	}
	// Underflow is not overflow: Python's float("1e-400") is 0.0.
	if res, err := ParseJSON("-1e-400"); err != nil || res.Value.F != 0 || !math.Signbit(res.Value.F) {
		t.Errorf("-1e-400 should underflow to -0.0: %+v %v", res.Value, err)
	}
	// CPython 3.13's json.loads accepts containers nested 9997 deep below
	// the top-level object and raises RecursionError one deeper.
	nested := func(n int, inner string) string {
		return `{"x":` + strings.Repeat("[", n) + inner + strings.Repeat("]", n) + "}"
	}
	if _, err := ParseJSON(nested(9997, "1")); err != nil {
		t.Errorf("9997 nested arrays parse in CPython 3.13 json: %v", err)
	}
	if _, err := ParseJSON(nested(9997, "[]")); err == nil {
		t.Error("9998 nested arrays must be rejected (json.loads raises RecursionError)")
	}
	if _, err := ParseJSON(strings.Repeat("9", 4300)); err != nil {
		t.Errorf("4300 digits is within Python's limit: %v", err)
	}
}

func TestWriteJSONStringMatchesPython(t *testing.T) {
	var b strings.Builder
	writeJSONString(&b, "\"\\\x00\x1f\b\f\n\r\t\x7f\u2028\u00E9\U0001F600")
	want := `"\"\\\u0000\u001f\b\f\n\r\t` + "\x7f\u2028\u00E9\U0001F600" + `"`
	if b.String() != want {
		t.Errorf("got %s want %s", b.String(), want)
	}
}

func TestFloatReprMatchesPython(t *testing.T) {
	// Expected values are CPython json.dumps output.
	cases := map[float64]string{
		1.0: "1.0", 1.5: "1.5", 0.0: "0.0", 1e16: "1e+16", 1e15: "1000000000000000.0",
		100.0: "100.0", 1e-5: "1e-05", 0.0001: "0.0001", 2.5e-7: "2.5e-07",
		123456789.125: "123456789.125", 1.7976931348623157e308: "1.7976931348623157e+308",
		5e-324: "5e-324", 0.1: "0.1", -1.5e22: "-1.5e+22", 9999999999999998.0: "9999999999999998.0",
		1.2345678901234567e19: "1.2345678901234567e+19", math.Pi: "3.141592653589793", 1e100: "1e+100",
	}
	for x, want := range cases {
		if got, ok := floatRepr(x); !ok || got != want {
			t.Errorf("repr(%g) = %q, want %q", x, got, want)
		}
	}
	if got, _ := floatRepr(math.Copysign(0, -1)); got != "-0.0" {
		t.Errorf("negative zero: %q", got)
	}
	for _, x := range []float64{math.Inf(1), math.Inf(-1), math.NaN()} {
		if _, ok := floatRepr(x); ok {
			t.Errorf("%g must have no repr", x)
		}
	}
}

func TestPythonStringHelpers(t *testing.T) {
	if got := pyStrip("\x1c\u0085 x \u00A0"); got != "x" {
		t.Errorf("pyStrip: %q", got)
	}
	if got := pyStrip("\uFEFFx\uFEFF"); got != "\uFEFFx\uFEFF" {
		t.Errorf("pyStrip must keep U+FEFF: %q", got)
	}
	for in, want := range map[string]string{"a'b": `"a'b"`, "a'b\"": `'a\'b"'`, "x\x01\n": `'x\x01\n'`, "\u00E9": "'\u00E9'"} {
		if got := reprStr(in); got != want {
			t.Errorf("reprStr(%q) = %s, want %s", in, got, want)
		}
	}
	if intRepr("-0") != "0" || intRepr("-10") != "-10" {
		t.Error("intRepr")
	}
	if got := SafeString("a\x1b[2J\nb\u009b\x7f", 0); got != `a\x1b[2J\x0ab\x9b\x7f` {
		t.Errorf("SafeString: %s", got)
	}
	if got := SafeString(strings.Repeat("\u00E9", 301), 300); got != strings.Repeat("\u00E9", 300)+"\u2026" {
		t.Errorf("SafeString truncation: %d runes", len([]rune(got)))
	}
}

func TestDecodeBlockFollowsCPythonValidate(t *testing.T) {
	ok := map[string]string{"QQ==": "A", "QR==": "A", "": "", " Q\tQ\r\n=\n=\n": "A"}
	for in, want := range ok {
		got, valid := decodeBlock(in)
		if !valid || string(got) != want {
			t.Errorf("decodeBlock(%q) = %q, %v", in, got, valid)
		}
	}
	// ERRATA E12: only ASCII space, tab, CR and LF may be stripped; any other
	// whitespace (VT, FF, U+001C-U+001F, NEL, NBSP, ideographic space) is invalid.
	for _, bad := range []string{"QQ=", "QQ", "QQ==QQ==", "=QQ=", "Q===", "QQ-_", "QQ\u200B==",
		"QQ\v==", "QQ\f==", "QQ\x1c==", "QQ\u0085==", "QQ\u00A0==", "QQ\u3000==", "QQ==\u2028"} {
		if _, valid := decodeBlock(bad); valid {
			t.Errorf("decodeBlock(%q) should fail", bad)
		}
	}
}

func TestCanonicalForm(t *testing.T) {
	// U+FFFF sorts before U+10000 by code point (UTF-16 order would differ).
	res, err := ParseJSON("{\"\U00010000\":\"a\",\"\uFFFF\":\"b\",\"b\":\"c\",\"a\":[1.0,-0,true,null]}")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := canonical(res.Value)
	if want := "{\"a\":[1.0,0,true,null],\"b\":\"c\",\"\uFFFF\":\"b\",\"\U00010000\":\"a\"}"; got != want {
		t.Errorf("got %s want %s", got, want)
	}
	a, _ := ParseJSON("{\"t\":\"Cafe\u0301\",\"payload_hash\":\"x\"}")
	b, _ := ParseJSON("{\"t\":\"Caf\u00E9\"}")
	ha, _ := PayloadHash(a.Value)
	hb, _ := PayloadHash(b.Value)
	if ha != hb {
		t.Error("payload hash must ignore payload_hash and normalize to NFC")
	}
	// ParseJSON never yields one, but a caller can build a Value by hand.
	inf := Value{Kind: Object, Obj: []Member{{"x", Value{Kind: Float, F: math.Inf(1)}}}}
	if _, err := PayloadHash(inf); err == nil {
		t.Error("an infinite float must have no canonical form")
	}
}

func TestBodyNormalization(t *testing.T) {
	if got := NormalizeBody("\u0085 a \t\r\nb\rc  \n"); got != "a\nb\nc" {
		t.Errorf("got %q", got)
	}
	if got := NormalizeBody("x\u00A0\ny"); got != "x\u00A0\ny" {
		t.Errorf("only space and tab are stripped at line ends: %q", got)
	}
}

func TestFindBlocksMatchesPythonFindall(t *testing.T) {
	b := func(s string) []string { return findBlocks(s) }
	cases := []struct {
		in   string
		want []string
	}{
		{"-----BEGIN KNOBE B64-----\nAA\n-----END KNOBE B64-----", []string{"AA"}},
		{"x-----BEGIN KNOBE B64-----\nAA\n-----END KNOBE B64-----", nil},
		{"\n-----BEGIN KNOBE B64-----\nA\n-----END KNOBE B64-----\n-----BEGIN KNOBE B64-----\nB\n-----END KNOBE B64-----", []string{"A", "B"}},
		{"\n-----BEGIN KNOBE B64-----\n\n-----END KNOBE B64-----", []string{""}},
		{"\n-----BEGIN KNOBE B64-----\nA\n", nil},
	}
	for _, c := range cases {
		if got := b(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("findBlocks(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFrontmatterHelpers(t *testing.T) {
	for in, want := range map[string]string{
		`spec_version: "1.0"`: "1.0", "  spec_version :'1.0'  ": "1.0", "spec_version:   ": "",
	} {
		if got, ok := specVersionLine(in); !ok || got != want {
			t.Errorf("specVersionLine(%q) = %q, %v", in, got, ok)
		}
	}
	for _, in := range []string{"spec_version:", "spec_versionx: 1"} {
		if _, ok := specVersionLine(in); ok {
			t.Errorf("specVersionLine(%q) should not match", in)
		}
	}
	if got, ok := findBodyStart("---\na: '---x'\n---\nbody"); !ok || got != 18 {
		t.Errorf("findBodyStart: %d %v", got, ok)
	}
	if _, ok := findBodyStart("\uFEFF---\n---\n"); ok {
		t.Error("findBodyStart must not skip a BOM")
	}
	if _, ok := findBodyStart("---\nno close"); ok {
		t.Error("findBodyStart needs a closing line")
	}
}

func TestConformanceHelpers(t *testing.T) {
	h := strings.Repeat("a", 64)
	str := func(s string) Value { return Value{Kind: String, S: s} }
	// ERRATA E12: exactly 64 lowercase ASCII hex characters, nothing after.
	if !hex64(str(h)) || hex64(str(h+"\n")) || hex64(str(h+"\n\n")) || hex64(str(strings.Repeat("A", 64))) ||
		hex64(str(h[1:]+"\n")) || hex64(str(h+" ")) {
		t.Error("hex64")
	}
	if !isRealISODate("2024-02-29") || isRealISODate("2026-02-29") || isRealISODate("0000-01-01") || isRealISODate("2026-13-01") {
		t.Error("isRealISODate")
	}
	// ERRATA E12: exactly ten ASCII characters [0-9]{4}-[0-9]{2}-[0-9]{2}.
	if !isoDateShape("2026-01-01") || !isoDateShape("2026-02-31") || isoDateShape("\u0662\u0660\u0662\u0666-01-01") ||
		isoDateShape("2026-01-01\n") || isoDateShape("2026-1-01") || isoDateShape("2026-01-1\n") || isoDateShape("2026/01/01") {
		t.Error("isoDateShape")
	}
}

// The walk mirrors lens.py _has_lone_surrogate, which spends two CPython
// frames per nesting level and so exhausts the 1000-frame recursion limit on
// any value or key nested 499 levels deep. It stops at whichever comes first
// in document order: a lone surrogate, or a value too deep to reach.
func TestScanPayloadFollowsLensWalk(t *testing.T) {
	deep := func(n int, inner string) string { return strings.Repeat("[", n) + inner + strings.Repeat("]", n) }
	for in, want := range map[string]scanResult{
		`{"x":` + deep(498, "") + `}`:                             scanClean,
		`{"x":` + deep(499, "") + `}`:                             scanTooDeep,
		`{"x":` + deep(497, "0") + `}`:                            scanClean,
		`{"x":` + deep(498, "0") + `}`:                            scanTooDeep,
		`{"x":` + deep(498, `"s"`) + `}`:                          scanTooDeep,
		`{"x":` + deep(497, "{}") + `}`:                           scanClean,
		`{"x":` + deep(497, `{"k":null}`) + `}`:                   scanTooDeep,
		`{"a":"\ud800","x":` + deep(499, "") + `}`:                scanLoneSurrogate,
		`{"x":` + deep(499, "") + `,"a":"\ud800"}`:                scanTooDeep,
		`{"\udc00":"v"}`:                                          scanLoneSurrogate,
		`{"x":[1,{"y":"ok"},"\ud83d\ude00"]}`:                     scanClean,
		`{"x":["ok",{"y":["\ud800"]}],"z":` + deep(499, "") + `}`: scanLoneSurrogate,
	} {
		res, err := ParseJSON(in)
		if err != nil {
			t.Fatalf("%.60s: %v", in, err)
		}
		if got := scanPayload(res.Value); got != want {
			t.Errorf("%.60s...: got %d, want %d", in, got, want)
		}
	}
}

func TestVerifyReportsHostilePayloadsAsLensDoes(t *testing.T) {
	file := func(payload string) []byte {
		return []byte("---\n---\n" + block(payload))
	}
	r := VerifyBytes(file(`{"title":"T","payload_hash":1e400}`))
	if r.Status != Unreadable || r.Stored != nil || r.BlockCount != 1 ||
		r.Reason != "payload contains a non-JSON numeric constant (NaN/Infinity); rejected" {
		t.Errorf("overflowing payload_hash: %+v", r)
	}
	if strings.Contains(r.JSON(), "Infinity\n") || strings.Contains(r.JSON(), "Infinity,") {
		t.Errorf("--json must never print a bare Infinity:\n%s", r.JSON())
	}
	r = VerifyBytes(file(`{"x":` + strings.Repeat("[", 499) + strings.Repeat("]", 499) + `}`))
	if r.Status != Unreadable || r.BlockCount != 0 || r.Payload != nil ||
		r.Reason != "verifier error (RecursionError); rejected" {
		t.Errorf("payload too deep for lens.py's walk: %+v", r)
	}
	// The lone-surrogate check now runs before the NFC and spec_version gates.
	r = VerifyBytes(file(`{"spec_version":"2.0","a":"\ud800"}`))
	if r.Status != Unreadable || r.Payload != nil || r.BlockCount != 1 ||
		r.Reason != "payload contains characters that cannot be UTF-8 encoded (e.g. an unpaired surrogate); rejected" {
		t.Errorf("lone surrogate before spec_version: %+v", r)
	}
	// lens.py shows safe(str(spec_version)): Python str() of the value, escaped and cut at 300.
	r = VerifyBytes(file(`{"spec_version":["1.0",` + strings.Repeat(`"xxxxxxxx",`, 40) + `"1.0"]}`))
	if want := "unsupported spec_version: ['1.0', " + strings.Repeat("'xxxxxxxx', ", 24); r.Status != Unreadable ||
		!strings.HasPrefix(r.Reason, want) || !strings.HasSuffix(r.Reason, "\u2026") {
		t.Errorf("list spec_version: %q", r.Reason)
	}
}

func TestHumanOutputEscapesControlCharacters(t *testing.T) {
	r := Report{
		Status: Verified, Conformance: Valid, BodyVerified: BodyOmitted, BlockCount: 1,
		Payload: &Value{Kind: Object, Obj: []Member{{"title", Value{Kind: String, S: "x\x1b[32m\nstatus: verified"}}}},
		Stored:  &Value{Kind: String, S: "h\x1b"}, ConformanceIssues: []string{"bad \x1b key"},
	}
	var buf bytes.Buffer
	r.WriteHuman(&buf)
	out := buf.String()
	if strings.ContainsAny(out, "\x1b") || strings.Contains(out, "\nstatus: verified") {
		t.Errorf("raw control characters reached the output:\n%s", out)
	}
}

func TestVerifyIsTotalOnGarbage(t *testing.T) {
	// No input may panic.
	inputs := []string{"", "---", "\n-----BEGIN KNOBE B64-----\n\n-----END KNOBE B64-----",
		"-----BEGIN KNOBE B64-----\ne30=\n-----END KNOBE B64-----", "\xff\xfe"}
	for _, in := range inputs {
		r := VerifyBytes([]byte(in))
		if r.Status == "" || r.Conformance == "" {
			t.Errorf("%q: incomplete report %+v", in, r)
		}
	}
}

func TestVerifyFileBoundsInputSize(t *testing.T) {
	dir := t.TempDir()
	big := dir + "/big.knobe.md"
	if err := os.WriteFile(big, make([]byte, MaxFileSize+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := VerifyFile(big); r.Status != Unreadable || !strings.Contains(r.Reason, "size limit") {
		t.Errorf("oversized file: %s %q", r.Status, r.Reason)
	}
	if r := VerifyFile(dir); r.Status != Unreadable || !strings.Contains(r.Reason, "directory") {
		t.Errorf("directory: %s %q", r.Status, r.Reason)
	}
}
