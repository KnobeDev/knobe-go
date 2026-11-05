package knobe

import (
	"errors"
	"io/fs"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// Expected values below are CPython 3.13 output (patched lens.py safe(),
// repr(), bytes.decode() and os.strerror() on glibc).

func TestSafeStringEscapesExactlyTheDisplaySet(t *testing.T) {
	for in, want := range map[string]string{
		// C0, DEL and C1 as \xNN; U+00A0 is kept.
		"a\x1b[2J\nb\u009b\x7f\x00\x1f\u0080\u009f\u00a0": `a\x1b[2J\x0ab\x9b\x7f\x00\x1f\x80\x9f` + "\u00a0",
		// Bidi embeddings, overrides and isolates and U+2028/U+2029 as \uNNNN.
		"safe\u202aa\u202bb\u202cc\u202dd\u202ee\u2066f\u2067g\u2068h\u2069i\u2028j\u2029k": `safe\u202aa\u202bb\u202cc\u202dd\u202ee\u2066f\u2067g\u2068h\u2069i\u2028j\u2029k`,
		// Neighbours of the set are kept.
		"x\u2029\u202f\u2065\u206a\u2027": `x\u2029` + "\u202f\u2065\u206a\u2027",
		// Other format characters (ZWSP, ZWJ, soft hyphen, BOM, ALM, LRM,
		// RLM) and backslashes are kept as they are.
		"zw\u200bj\u200d\u00ad\ufeff\u061c\u200e\u200f\\": "zw\u200bj\u200d\u00ad\ufeff\u061c\u200e\u200f\\",
		// Unpaired surrogates, as the parser keeps them (WTF-8).
		wtf8(0xD800) + "x" + wtf8(0xDFFF): `\ud800x\udfff`,
		wtf8(0xDBFF) + wtf8(0xDC00):       `\udbff\udc00`,
	} {
		if got := SafeString(in, 0); got != want {
			t.Errorf("SafeString(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestSafeStringTruncatesAfterEscaping(t *testing.T) {
	k := strings.Repeat("k", 300)
	for _, c := range []struct{ in, want string }{
		{k, k},
		{k + "k", k + "…"},
		{strings.Repeat("\U0001F600", 301), strings.Repeat("\U0001F600", 300) + "…"},
		// An escape that crosses the limit is cut inside the escape.
		{k[:298] + "\x1bz", k[:298] + `\x` + "…"},
		{k[:294] + "\u202e", k[:294] + `\u202e`},
		{k[:294] + "\u202ez", k[:294] + `\u202e` + "…"},
		{k[:296] + "\u202e", k[:296] + `\u20` + "…"},
		{k[:299] + wtf8(0xDC00), k[:299] + `\` + "…"},
	} {
		if got := SafeString(c.in, 300); got != c.want {
			t.Errorf("SafeString(%.20q…, 300) = …%s, want …%s", c.in, tail(got), tail(c.want))
		}
		if got := SafeString(c.in, 0); strings.HasSuffix(got, "…") {
			t.Errorf("SafeString(…, 0) must not truncate: …%s", tail(got))
		}
	}
}

func tail(s string) string {
	r := []rune(s)
	if len(r) > 12 {
		r = r[len(r)-12:]
	}
	return string(r)
}

func TestDuplicateKeyReasonShowsSurrogates(t *testing.T) {
	file := func(payload string) []byte { return []byte("---\n---\n" + block(payload)) }
	for payload, key := range map[string]string{
		`{"\ud800":"1","\ud800":"2"}`:           `\ud800`,
		`{"x\udfffy":"1","x\udfffy":"2"}`:       `x\udfffy`,
		`{"\u001b\udc00":"1","\u001b\udc00":2}`: `\x1b\udc00`,
		`{"a\u202eb":"1","a\u202eb":"2"}`:       `a\u202eb`,
	} {
		r := VerifyBytes(file(payload))
		if want := "payload contains duplicate JSON key: " + key + " (ambiguous; rejected)"; r.Reason != want {
			t.Errorf("%s:\n got %s\nwant %s", payload, r.Reason, want)
		}
		if strings.ContainsRune(r.JSON(), '\uFFFD') {
			t.Errorf("%s: a surrogate must never show as U+FFFD:\n%s", payload, r.JSON())
		}
	}
	// Distinct lone surrogates, or one and a real U+FFFD, are distinct keys.
	for _, payload := range []string{`{"\ud800":"1","\udc00":"2"}`, `{"\ud800":"1","\ufffd":"2"}`} {
		if r := VerifyBytes(file(payload)); !strings.HasPrefix(r.Reason, "payload contains characters that cannot be UTF-8 encoded") {
			t.Errorf("%s: %s", payload, r.Reason)
		}
	}
}

func TestReprMatchesPython(t *testing.T) {
	in := "a\x1b\u202e" + wtf8(0xDCFF) + "\U000E0001\U000F0000\u0378\u2fff\U0002EBF0\u00a0\u3000 '\""
	want := `'a\x1b\u202e\udcff\U000e0001\U000f0000\u0378` + "\u2fff\U0002EBF0" + `\xa0\u3000 \'"'`
	if got := reprStr(in); got != want {
		t.Errorf("reprStr = %s, want %s", got, want)
	}
	for in, want := range map[string]string{"it's": `"it's"`, "a'b\"": `'a\'b"'`, `\`: `'\\'`, "\t\r\n": `'\t\r\n'`} {
		if got := reprStr(in); got != want {
			t.Errorf("reprStr(%q) = %s, want %s", in, got, want)
		}
	}
}

// pyPrintable must agree with str.isprintable() on every code point. The
// Unicode version matters, so this runs on Python 3.13 (Unicode 15.1) only.
func TestPyPrintableMatchesPython(t *testing.T) {
	requirePython(t)
	if pythonVersion() != "3.13" {
		t.Skipf("python3 is %s; pyPrintable follows 3.13's Unicode 15.1", pythonVersion())
	}
	out, err := exec.Command("python3", "-c",
		"print(','.join('%x' % c for c in range(0x110000) if chr(c).isprintable()))").Output()
	if err != nil {
		t.Fatal(err)
	}
	printable := map[rune]bool{}
	for _, h := range strings.Split(strings.TrimSpace(string(out)), ",") {
		var r rune
		for _, c := range h {
			r = r*16 + rune(strings.IndexRune("0123456789abcdef", c))
		}
		printable[r] = true
	}
	bad := 0
	for r := rune(0); r < 0x110000; r++ {
		if pyPrintable(r) != printable[r] {
			if bad++; bad <= 10 {
				t.Errorf("U+%04X: pyPrintable %v, Python %v", r, pyPrintable(r), printable[r])
			}
		}
	}
	if bad > 10 {
		t.Errorf("%d code points disagree in all", bad)
	}
}

// The ten cases knobe-rs pins (src/verify.rs), plus a few more.
func TestUTF8ErrorTextMatchesCPython(t *testing.T) {
	for in, want := range map[string]string{
		"ab\xc3(":          "byte 0xc3 in position 2: invalid continuation byte",
		"\xff":             "byte 0xff in position 0: invalid start byte",
		"\x80x":            "byte 0x80 in position 0: invalid start byte",
		"\xc0\xaf":         "byte 0xc0 in position 0: invalid start byte",
		"\xed\xa0\x80":     "byte 0xed in position 0: invalid continuation byte",
		"\xe0\x80\x80":     "byte 0xe0 in position 0: invalid continuation byte",
		"\xe2\x82(":        "bytes in position 0-1: invalid continuation byte",
		"x\xf0\x9f\x98(":   "bytes in position 1-3: invalid continuation byte",
		"\xc3":             "byte 0xc3 in position 0: unexpected end of data",
		"\xf0\x9f\x98":     "bytes in position 0-2: unexpected end of data",
		"\xf4\x90\x80\x80": "byte 0xf4 in position 0: invalid continuation byte",
		"\xf4\x8f\xbf":     "bytes in position 0-2: unexpected end of data",
		"\xf5\x80":         "byte 0xf5 in position 0: invalid start byte",
		"x\xe0\xa0":        "bytes in position 1-2: unexpected end of data",
		"\xc2":             "byte 0xc2 in position 0: unexpected end of data",
		"\U0001F600\xff":   "byte 0xff in position 4: invalid start byte",
	} {
		r := VerifyBytes([]byte(in))
		if want := "file is not valid UTF-8: 'utf-8' codec can't decode " + want; r.Reason != want {
			t.Errorf("%q:\n got %s\nwant %s", in, r.Reason, want)
		}
	}
	if got := utf8ErrorText([]byte("ok \U0001F600")); got != "" {
		t.Errorf("valid UTF-8: %q", got)
	}
}

func TestPathsShowAsPythonHoldsThem(t *testing.T) {
	for in, want := range map[string]string{
		"/tmp/a\xffb":         `/tmp/a\udcffb`,
		"/tmp/\xed\xa0\x80":   `/tmp/\udced\udca0\udc80`,
		"/tmp/\xe2\x82(":      `/tmp/\udce2\udc82(`,
		"/tmp/\x1b[31m\u202e": `/tmp/\x1b[31m\u202e`,
		"/tmp/caf\u00e9 \\":   "/tmp/caf\u00e9 \\",
	} {
		if got := safePath(in); got != want {
			t.Errorf("safePath(%q) = %s, want %s", in, got, want)
		}
	}
	pathErr := func(op string, errno syscall.Errno) error {
		return &fs.PathError{Op: op, Path: "/x\xff", Err: errno}
	}
	for _, c := range []struct {
		err  error
		want string
	}{
		{pathErr("open", syscall.ENOENT), `file not found: /x\udcff`},
		{pathErr("read", syscall.EISDIR), `path is a directory, not a file: /x\udcff`},
		{pathErr("open", syscall.EACCES), `could not read file: [Errno 13] Permission denied: '/x\udcff'`},
		{pathErr("read", syscall.EIO), `could not read file: [Errno 5] Input/output error`},
		{errors.New("odd\x1b"), `could not read file: odd\x1b`},
	} {
		if got := readErrorReason("/x\xff", c.err); got != c.want {
			t.Errorf("%v:\n got %s\nwant %s", c.err, got, c.want)
		}
	}
}

func TestStrerrorMatchesGlibc(t *testing.T) {
	requirePython(t)
	if runtime.GOOS != "linux" {
		t.Skip("strerror follows glibc's wording")
	}
	code := "import os\nfor i in range(1, 134): print(os.strerror(i))"
	out, err := exec.Command("python3", "-c", code).Output()
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if got := strerror(syscall.Errno(i + 1)); got != want {
			t.Errorf("errno %d: %q, want %q", i+1, got, want)
		}
	}
}

func TestHumanFieldsAreSafeStr(t *testing.T) {
	str := func(s string) Value { return Value{Kind: String, S: s} }
	long := Value{Kind: Array}
	for i := 0; i < 40; i++ {
		long.Arr = append(long.Arr, str("xxxxxxxx"))
	}
	longRepr := repr(long)
	for _, c := range []struct {
		stored Value
		title  Value
		want   []string
	}{
		{str("h\x1b\u202e\n"), str("t\u2028"), []string{`stored_hash:       h\x1b\u202e\x0a`, `title:             t\u2028`}},
		{long, long, []string{"stored_hash:       " + string([]rune(longRepr)[:300]) + "…", "title:             " + longRepr}},
		{Value{Kind: Null}, str(strings.Repeat("t", 301)), []string{"stored_hash:       None", "title:             " + strings.Repeat("t", 300) + "…"}},
		{Value{Kind: Int, Num: "5"}, Value{Kind: Bool, B: true}, []string{"stored_hash:       5", "title:             True"}},
	} {
		p := Value{Kind: Object, Obj: []Member{{"title", c.title}, {"privacy_level", long}}}
		r := Report{Status: Failed, Conformance: Valid, BodyVerified: BodyOmitted, BlockCount: 1, Payload: &p, Stored: &c.stored}
		var b strings.Builder
		r.WriteHuman(&b)
		for _, line := range append(c.want, "spec_version:      None", "privacy_level:     "+string([]rune(longRepr)[:300])+"…") {
			if !strings.Contains(b.String(), line+"\n") {
				t.Errorf("missing line %q in:\n%s", line, b.String())
			}
		}
	}
}

func TestParserDepthFollowsCPython313(t *testing.T) {
	nest := func(n int, inner string) string { return strings.Repeat("[", n) + inner + strings.Repeat("]", n) }
	var pe *ParseError
	for _, c := range []struct {
		level int
		node  string
		want  string // "", "syntax", "nonconst", "dup"
	}{
		{9995, "{}", ""}, {9996, "{}", "syntax"},
		{9995, `{"a":1,"a":2}`, "dup"}, {9996, `{"a":1,"a":2}`, "syntax"},
		{9995, "1.5", ""}, {9996, "1.5", "syntax"}, {9996, "-0e1", "syntax"},
		{9995, "1e400", "nonconst"}, {9996, "1e400", "syntax"},
		{9995, "NaN", "nonconst"}, {9996, "NaN", "syntax"}, {9996, "-Infinity", "syntax"},
		{9997, "[]", ""}, {9998, "[]", "syntax"},
		{9998, "0", ""}, {9998, "-12", ""}, {9998, `"s"`, ""}, {9998, "null", ""}, {9998, "true", ""},
	} {
		_, err := ParseJSON(nest(c.level, c.node))
		got := ""
		switch {
		case err == nil:
		case errors.As(err, &pe) && pe.IsDuplicate:
			got = "dup"
		case errors.As(err, &pe) && pe.NonJSONConst:
			got = "nonconst"
		default:
			got = "syntax"
		}
		if got != c.want {
			t.Errorf("%s at level %d: got %q, want %q (%v)", c.node, c.level, got, c.want, err)
		}
	}
}
