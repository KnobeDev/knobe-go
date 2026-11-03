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
	for _, in := range []string{"[NaN]", "-Infinity", "Infinity"} {
		if _, err := ParseJSON(in); !errors.As(err, &pe) || !pe.NonJSONConst {
			t.Errorf("%s: want NonJSONConst, got %v", in, err)
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
	res, _ = ParseJSON("1e400")
	if !math.IsInf(res.Value.F, 1) {
		t.Errorf("1e400 should overflow to +Inf: %+v", res.Value)
	}
	nested := func(n int) string { return `{"x":` + strings.Repeat("[", n) + strings.Repeat("]", n) + "}" }
	if _, err := ParseJSON(nested(996)); err != nil {
		t.Errorf("996 nested arrays verify in lens.py: %v", err)
	}
	if _, err := ParseJSON(nested(997)); err == nil {
		t.Error("997 nested arrays must be rejected (lens.py crashes there)")
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
	ok := map[string]string{"QQ==": "A", "QR==": "A", "": "", " Q\tQ\u00A0=\x1c=\n": "A"}
	for in, want := range ok {
		got, valid := decodeBlock(in)
		if !valid || string(got) != want {
			t.Errorf("decodeBlock(%q) = %q, %v", in, got, valid)
		}
	}
	for _, bad := range []string{"QQ=", "QQ", "QQ==QQ==", "=QQ=", "Q===", "QQ-_", "QQ\u200B=="} {
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
	inf, _ := ParseJSON(`{"x":1e999}`)
	if _, err := PayloadHash(inf.Value); err == nil {
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
	if !hex64(str(h)) || !hex64(str(h+"\n")) || hex64(str(h+"\n\n")) || hex64(str(strings.Repeat("A", 64))) {
		t.Error("hex64")
	}
	if !isRealISODate("2024-02-29") || isRealISODate("2026-02-29") || isRealISODate("0000-01-01") || isRealISODate("2026-13-01") {
		t.Error("isRealISODate")
	}
	if !isoDateShape("\u0662\u0660\u0662\u0666-01-01") || !isoDateShape("2026-01-01\n") || isoDateShape("2026-1-01") {
		t.Error("isoDateShape")
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

func TestSafeStringEscapesBidiAndFormatControls(t *testing.T) {
	in := "safe" + string(rune(0x202E)) + "evil" + string(rune(0x2066)) + "x" +
		string(rune(0x200B)) + string(rune(0xFEFF)) + string(rune(0x2028))
	if got, want := SafeString(in, 0), `safe\u202eevil\u2066x\u200b\ufeff\u2028`; got != want {
		t.Errorf("got %s want %s", got, want)
	}
	in = "a" + string(rune(0x2067)) + "b" + string(rune(0x061C)) + "c"
	if got, want := reprStr(in), `'a\u2067b\u061cc'`; got != want {
		t.Errorf("reprStr must escape Cf characters: got %s want %s", got, want)
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
