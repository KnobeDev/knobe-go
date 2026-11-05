package knobe

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Differential parity with the reference verifier: for every published file
// and for a battery of crafted hostile files, this verifier must report
// exactly what `python3 lens.py --json` reports on the fields the upstream
// parity harness compares (state, conformance, body_verified, computed,
// stored, block_count, multiple_blocks, exit code).

func TestPublishedCorpusMatchesLens(t *testing.T) {
	requirePython(t)
	files := corpus(t)
	for _, f := range files {
		py, ok := lens(t, f)
		if !ok {
			t.Errorf("lens.py crashed on %s", f)
			continue
		}
		if got := ours(t, f); got != py {
			t.Errorf("%s\n  lens: %+v\n  ours: %+v", f, py, got)
		}
	}
	t.Logf("compared %d published files", len(files))
}

const (
	fm   = "---\ntitle: \"T\"\nspec_version: \"1.0\"\n---\n"
	base = `"spec_version":"1.0","title":"T","summary":"S","content_type":"original","created_date":"2026-01-02","license":"CC0-1.0","privacy_level":"public","quarantine_status":"quarantine","attribution":{"sources":[{"author":"A"}]}`
)

// oracle hashes with the reference algorithms in Python, so fixtures are
// never sealed by the code under test.
func oracle(t *testing.T, mode, input string) string {
	t.Helper()
	cmd := exec.Command("python3", filepath.Join("testdata", "pyhash.py"), mode)
	cmd.Env = append(os.Environ(), "KNOBE_PROTOCOL_DIR="+protocolDir(t))
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("pyhash oracle failed on %q: %v", input, err)
	}
	return strings.TrimSpace(string(out))
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// sealed fills __B__ with the oracle body hash of body, then __H__ with the
// oracle payload hash of the resulting payload text.
func sealed(t *testing.T, payload, body string) string {
	p := strings.ReplaceAll(payload, "__B__", oracle(t, "body", body))
	if strings.Contains(p, "__H__") {
		h := oracle(t, "payload", strings.ReplaceAll(p, `"__H__"`, "null"))
		p = strings.ReplaceAll(p, "__H__", h)
	}
	return p
}

func block(payloadText string) string {
	return "\n" + BeginMarker + "\n" + b64(payloadText) + "\n" + EndMarker + "\n"
}

func knobeFile(t *testing.T, front, body, payload string) []byte {
	return []byte(front + body + block(sealed(t, payload, body)))
}

func obj(extra string) string {
	if extra == "" {
		return "{" + base + `,"payload_hash":"__H__"}`
	}
	return "{" + base + "," + extra + `,"payload_hash":"__H__"}`
}

// objWithout is the base fields minus drop, plus extra, plus payload_hash.
func objWithout(drop, extra string) string {
	var fields []string
	for _, f := range splitTopLevel(base) {
		if !strings.HasPrefix(f, `"`+drop+`"`) {
			fields = append(fields, f)
		}
	}
	if extra != "" {
		fields = append(fields, extra)
	}
	return "{" + strings.Join(fields, ",") + `,"payload_hash":"__H__"}`
}

func noHash(s string) string { return strings.Replace(s, `,"payload_hash":"__H__"`, "", 1) }

func splitTopLevel(s string) []string {
	var out []string
	depth, start, inStr, esc := 0, 0, false, false
	for i, c := range s {
		switch {
		case esc:
			esc = false
		case c == '\\' && inStr:
			esc = true
		case c == '"':
			inStr = !inStr
		case (c == '{' || c == '[') && !inStr:
			depth++
		case (c == '}' || c == ']') && !inStr:
			depth--
		case c == ',' && !inStr && depth == 0:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

type hostileCase struct {
	name string
	data []byte
}

func hostileCases(t *testing.T) []hostileCase {
	hex := strings.Repeat("a", 64)
	body := "\nHello body.\n"
	bh := `"body_hash":"__B__"`
	k := func(front, b, payload string) []byte { return knobeFile(t, front, b, payload) }
	cd := func(v string) string { return objWithout("created_date", `"created_date":`+v) }
	att := func(v string) string { return objWithout("attribution", `"attribution":`+v) }

	cases := []hostileCase{
		{"baseline", k(fm, "", obj(""))},
		{"baseline-with-body", k(fm, body, obj(bh))},
		// hash formats: ERRATA E12 allows nothing after the 64 hex characters
		{"payload-hash-trailing-newline", k(fm, "", noHash(objWithout("payload_hash", `"payload_hash":"`+hex+`\n"`)))},
		{"body-hash-trailing-newline", k(fm, body, obj(`"body_hash":"`+hex+`\n"`))},
		{"parent-hash-trailing-newline", k(fm, "", obj(`"parents":[{"title":"p","payload_hash":"`+hex+`\n"}]`))},
		{"parent-hash-uppercase", k(fm, "", obj(`"parents":[{"title":"p","payload_hash":"`+strings.Repeat("A", 64)+`"}]`))},
		{"parent-hash-missing-ok", k(fm, "", obj(`"parents":[{"title":"p"},"x",null]`))},
		{"parent-hash-null", k(fm, "", obj(`"parents":[{"payload_hash":null}]`))},
		{"parents-not-a-list", k(fm, "", obj(`"parents":{"payload_hash":"zz"}`))},
		{"payload-hash-missing", k(fm, "", noHash(objWithout("payload_hash", "")))},
		{"payload-hash-null", k(fm, "", strings.Replace(obj(""), `"__H__"`, "null", 1))},
		{"payload-hash-number", k(fm, "", strings.Replace(obj(""), `"__H__"`, "5", 1))},
		{"payload-hash-object", k(fm, "", strings.Replace(obj(""), `"__H__"`, `{"a":[1,"x"]}`, 1))},
		{"body-hash-null", k(fm, body, obj(`"body_hash":null`))},
		{"body-hash-number", k(fm, body, obj(`"body_hash":7`))},
		// numbers that overflow to infinity are unreadable (upstream PR #11)
		{"payload-hash-overflow", k(fm, "", strings.Replace(obj(""), `"__H__"`, "1e400", 1))},
		{"payload-hash-negative-overflow", k(fm, "", strings.Replace(obj(""), `"__H__"`, "-1E999", 1))},
		{"number-overflow-nested", k(fm, "", obj(`"x":{"y":[1,1.5e309]}`))},
		{"dup-key-then-overflow", k(fm, "", obj(`"ext":{"a":"1","a":1e400}`))},
		{"dup-key-then-nan", k(fm, "", obj(`"ext":{"a":"1","a":NaN}`))},
		{"dup-key-then-syntax-error", k(fm, "", `{"a":"1","a":"2",}`)},
		{"dup-key-inner-closes-first", k(fm, "", obj(`"a":{"b":"1","b":"2"},"a":"3"`))},
		// created_date (ERRATA E12: ASCII digits, nothing after)
		{"date-feb-29-nonleap", k(fm, "", cd(`"2026-02-29"`))},
		{"date-feb-29-leap", k(fm, "", cd(`"2024-02-29"`))},
		{"date-year-zero", k(fm, "", cd(`"0000-01-01"`))},
		{"date-arabic-indic-digits", k(fm, "", cd(`"\u0662\u0660\u0662\u0666-01-01"`))},
		{"date-trailing-newline", k(fm, "", cd(`"2026-01-01\n"`))},
		{"date-short-month", k(fm, "", cd(`"2026-1-01"`))},
		{"date-number", k(fm, "", cd(`20260101`))},
		{"date-month-13", k(fm, "", cd(`"2026-13-01"`))},
		// attribution / sources truthiness
		{"sources-empty-list", k(fm, "", att(`{"sources":[]}`))},
		{"sources-empty-object", k(fm, "", att(`{"sources":{}}`))},
		{"sources-nonempty-object", k(fm, "", att(`{"sources":{"a":1}}`))},
		{"sources-string", k(fm, "", att(`{"sources":"x"}`))},
		{"sources-empty-string", k(fm, "", att(`{"sources":""}`))},
		{"sources-zero", k(fm, "", att(`{"sources":0}`))},
		{"sources-zero-float", k(fm, "", att(`{"sources":0.0}`))},
		{"sources-true", k(fm, "", att(`{"sources":true}`))},
		{"sources-null", k(fm, "", att(`{"sources":null}`))},
		{"sources-absent", k(fm, "", att(`{}`))},
		{"attribution-string", k(fm, "", att(`"me"`))},
		{"attribution-null", k(fm, "", att(`null`))},
		{"attribution-list", k(fm, "", att(`[{"sources":[1]}]`))},
		// string-typed required fields
		{"title-number", k(fm, "", objWithout("title", `"title":5`))},
		{"title-bool", k(fm, "", objWithout("title", `"title":true`))},
		{"title-null", k(fm, "", objWithout("title", `"title":null`))},
		{"summary-list", k(fm, "", objWithout("summary", `"summary":[]`))},
		{"license-object", k(fm, "", objWithout("license", `"license":{}`))},
		{"summary-missing", k(fm, "", objWithout("summary", ""))},
		// spec_version
		{"spec-version-float", k(fm, "", objWithout("spec_version", `"spec_version":1.0`))},
		{"spec-version-2", k(fm, "", objWithout("spec_version", `"spec_version":"2.0"`))},
		{"spec-version-null", k(fm, "", objWithout("spec_version", `"spec_version":null`))},
		{"spec-version-padded", k(fm, "", objWithout("spec_version", `"spec_version":"1.0 "`))},
		{"spec-version-missing", k(fm, "", objWithout("spec_version", ""))},
		{"spec-version-list", k(fm, "", objWithout("spec_version", `"spec_version":["1.0"]`))},
		{"spec-version-object", k(fm, "", objWithout("spec_version", `"spec_version":{"v":"1.0"}`))},
		{"spec-version-bool", k(fm, "", objWithout("spec_version", `"spec_version":true`))},
		{"spec-version-long-list", k(fm, "", objWithout("spec_version", `"spec_version":[`+strings.Repeat(`"xxxxxxxx",`, 40)+`"1.0"]`))},
		// vocabulary
		{"vocab-custom-bare", k(fm, "", objWithout("content_type", `"content_type":"custom"`))},
		{"vocab-ext-prefix", k(fm, "", objWithout("content_type", `"content_type":"ext-custom"`))},
		{"vocab-namespaced", k(fm, "", objWithout("privacy_level", `"privacy_level":"acme:secret"`))},
		{"vocab-identity-status", k(fm, "", obj(`"identity_status":"vibes"`))},
		{"vocab-non-string", k(fm, "", obj(`"identity_status":["signed"]`))},
		// numbers: the hash must still match (ERRATA E1), conformance invalid
		{"numbers-ints", k(fm, "", obj(`"x":[0,-0,7,-12,123456789012345678901234567890]`))},
		{"numbers-floats", k(fm, "", obj(`"x":[1.0,1.5,-0.0,1e16,1E2,1e-5,0.0001,2.5e-7,123456789.125,1.7976931348623157e308,5e-324,1e22,0.1,9999999999999998.0,1e-400]`))},
		{"numbers-many-paths", k(fm, "", obj(`"n":{"a":1,"b":[2,3],"c":{"d":4}},"m":5,"o":6`))},
		{"numbers-bool-null-not-numeric", k(fm, "", obj(`"flag":true,"none":null,"deep":{"a":[false]}`))},
		// JSON strictness
		{"dup-key-nested", k(fm, "", obj(`"ext":{"a":"1","a":"2"}`))},
		{"nan-constant", k(fm, "", obj(`"x":NaN`))},
		{"infinity-constant", k(fm, "", obj(`"x":-Infinity`))},
		{"lone-surrogate-value", k(fm, "", obj(`"x":"\ud800"`))},
		{"lone-surrogate-key", k(fm, "", obj(`"\udc00":"v"`))},
		{"lone-surrogate-in-payload-hash", k(fm, "", strings.Replace(obj(""), `"__H__"`, `"\ud800"`, 1))},
		{"lone-surrogate-and-bad-spec-version", k(fm, "", objWithout("spec_version", `"spec_version":"2.0","a":"\ud800"`))},
		{"lone-surrogate-and-nfc-collision", k(fm, "", obj("\"caf\u00E9\":\"1\",\"cafe\u0301\":\"2\",\"a\":\"\\ud800\""))},
		{"surrogate-pair-escape", k(fm, "", obj(`"x":"\ud83d\ude00"`))},
		{"escapes-mixed", k(fm, "", obj(`"x":"\u0000\u001f\b\f\n\r\t\/\\\"\u007f \u00E9"`))},
		{"c1-and-del-literal", k(fm, "", obj("\"x\":\"a\u0085b\u009bc\u007fd\""))},
		{"nfd-key-no-collision", k(fm, "", obj("\"cafe\u0301\":\"v\",\"x\":\"e\u0301\""))},
		{"nfc-collision-in-list", k(fm, "", obj("\"x\":[{\"caf\u00E9\":\"1\",\"cafe\u0301\":\"2\"}]"))},
		{"astral-keys-sorting", k(fm, "", obj("\"\U0001F600\":\"a\",\"\uFFFF\":\"b\",\"\U00010000\":\"c\""))},
		{"payload-top-level-string", k(fm, "", `"hello"`)},
		{"payload-top-level-null", k(fm, "", "null")},
		{"payload-whitespace-around", k(fm, "", " \n\t"+obj("")+"\r\n ")},
		{"payload-trailing-comma", k(fm, "", `{"a":"1",}`)},
		{"payload-bom", k(fm, "", "\uFEFF"+obj(""))},
		{"payload-raw-control-char", k(fm, "", obj("\"x\":\"a\u0001b\""))},
		{"payload-raw-del-char", k(fm, "", obj("\"x\":\"a\u007fb\""))},
		{"payload-leading-zero", k(fm, "", obj(`"x":01`))},
		{"payload-bad-escape", k(fm, "", obj(`"x":"\q"`))},
		{"payload-short-unicode-escape", k(fm, "", obj(`"x":"\u12"`))},
		// frontmatter
		{"fm-missing", k("", "", obj(""))},
		{"fm-crlf", k("---\r\ntitle: T\r\nspec_version: 1.0\r\n---\r\n", "", obj(""))},
		{"fm-crlf-with-body", k("---\r\ntitle: T\r\n---\r\n", "Body\r\nline  \r\n", obj(bh))},
		{"fm-double-cr", k("---\r\r\ntitle: T\r\n---\r\n", "", obj(""))},
		{"fm-double-cr-with-body", k("---\r\r\ntitle: T\n---\n", body, obj(bh))},
		{"fm-bom", k("\uFEFF---\ntitle: T\n---\n", "", obj(""))},
		{"fm-bom-with-body", k("\uFEFF---\ntitle: T\n---\n", body, obj(bh))},
		{"fm-unclosed", k("---\ntitle: T\nspec_version: 2.0\n", "", obj(""))},
		{"fm-spec-quoted-mismatch", k("---\nspec_version: '1.1'\n---\n", "", obj(""))},
		{"fm-spec-mixed-quotes", k("---\nspec_version: \"'1.0'\"\n---\n", "", obj(""))},
		{"fm-spec-whitespace-only", k("---\nspec_version:    \n---\n", "", obj(""))},
		{"fm-spec-empty", k("---\nspec_version:\n---\n", "", obj(""))},
		{"fm-spec-indented-unicode-ws", k("---\n\u3000spec_version\u00A0:\u20031.1\u205F\n---\n", "", obj(""))},
		{"fm-spec-first-wins", k("---\nspec_version: 1.0\nspec_version: 9\n---\n", "", obj(""))},
		{"fm-spec-after-close-ignored", k("---\ntitle: T\n---\nspec_version: 9\n", "", obj(""))},
		{"fm-spec-not-prefix", k("---\nspec_versionx: 9\n---\n", "", obj(""))},
		// body normalization edges
		{"body-tabs-and-spaces", k(fm, "\n  a \t\n\tb\t \n\n", obj(bh))},
		{"body-lone-cr", k(fm, "\na\rb\r\n", obj(bh))},
		{"body-unicode-edges", k(fm, "\u001c\u0085\u00A0 body \u3000\u2028", obj(bh))},
		{"body-feff-edge", k(fm, "\uFEFFbody\uFEFF", obj(bh))},
		{"body-nbsp-line-end", k(fm, "\nline\u00A0\nnext \n", obj(bh))},
		{"body-with-dashes-line", k(fm, "\nbefore\n---\nafter\n", obj(bh))},
		{"body-nfd-not-normalized", k(fm, "\ncafe\u0301\n", obj(bh))},
		{"body-empty-with-hash", k(fm, "", obj(bh))},
		{"body-modified", bytes.Replace(k(fm, body, obj(bh)), []byte("Hello"), []byte("Jello"), 1)},
	}

	// Block-level structure, built by hand.
	good := sealed(t, obj(""), "")
	goodB64 := b64(good)
	withBH := sealed(t, obj(bh), body)
	wrap := func(s string) string {
		var parts []string
		for len(s) > 10 {
			parts, s = append(parts, s[:10]), s[10:]
		}
		return strings.Join(append(parts, s), "\n")
	}
	blk := func(content string) string { return "\n" + BeginMarker + "\n" + content + "\n" + EndMarker + "\n" }
	// JSON allows trailing whitespace; pad until the Base64 needs '=' padding.
	padded := good
	for len(padded)%3 == 0 {
		padded += " "
	}
	raw := func(s string) []byte { return []byte(s) }
	cases = append(cases,
		hostileCase{"block-wrapped-lines", raw(fm + blk(wrap(goodB64)))},
		hostileCase{"block-internal-spaces-tabs", raw(fm + blk(" "+strings.Replace(goodB64, "A", "A \t", 1)+" \t"))},
		// ERRATA E12: only ASCII space, tab, CR and LF may be stripped
		hostileCase{"block-internal-unicode-space", raw(fm + blk(goodB64+"\u00A0\u001c"))},
		hostileCase{"block-internal-zwsp", raw(fm + blk(goodB64+"\u200B"))},
		hostileCase{"nel-block-whitespace", raw(fm + blk(goodB64[:8]+"\u0085"+goodB64[8:]))},
		hostileCase{"block-internal-vt-ff", raw(fm + blk(goodB64[:8]+"\v"+goodB64[8:16]+"\f"+goodB64[16:]))},
		hostileCase{"block-internal-file-separators", raw(fm + blk(goodB64[:8]+"\x1c\x1d\x1e\x1f"+goodB64[8:]))},
		hostileCase{"block-internal-line-separator", raw(fm + blk(goodB64+"\u2028"))},
		hostileCase{"block-internal-crlf-wrapped", raw(fm + blk(strings.ReplaceAll(wrap(goodB64), "\n", "\r\n")))},
		hostileCase{"block-at-byte-zero", raw(BeginMarker + "\n" + goodB64 + "\n" + EndMarker + "\n")},
		hostileCase{"block-at-byte-zero-with-body-hash", raw(BeginMarker + "\n" + b64(withBH) + "\n" + EndMarker + "\n")},
		hostileCase{"block-no-end", raw(fm + "\n" + BeginMarker + "\n" + goodB64 + "\n")},
		hostileCase{"block-empty", raw(fm + blk(""))},
		hostileCase{"block-end-trailing-text", raw(fm + "\n" + BeginMarker + "\n" + goodB64 + "\n" + EndMarker + " trailing\n")},
		hostileCase{"block-begin-trailing-space", raw(fm + "\n" + BeginMarker + " \n" + goodB64 + "\n" + EndMarker + "\n")},
		hostileCase{"block-crlf-markers", raw(fm + "\r\n" + BeginMarker + "\r\n" + goodB64 + "\r\n" + EndMarker + "\r\n")},
		hostileCase{"block-two-then-garbage-last", raw(fm + block(good) + blk("!!!!"))},
		hostileCase{"block-two-with-body-hash", raw(fm + body + block(withBH) + block(withBH))},
		hostileCase{"block-nested-begin", raw(fm + "\n" + BeginMarker + "\n" + BeginMarker + "\n" + goodB64 + "\n" + EndMarker + "\n")},
		hostileCase{"b64-nonzero-trailing-bits", raw(fm + blk(flipTrailingBits(b64(padded))))},
		hostileCase{"b64-excess-after-padding", raw(fm + blk(goodB64+"QQ=="))},
		hostileCase{"b64-bad-alphabet", raw(fm + blk(goodB64[:len(goodB64)-2]+"-_"))},
		hostileCase{"b64-three-pad", raw(fm + blk("Q==="))},
		hostileCase{"b64-not-utf8-json", raw(fm + blk(base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe, 0x7b, 0x7d})))},
		// Nesting limits: lens.py's _has_lone_surrogate walk stops at 498
		// levels (499 is a RecursionError, reported as a verifier error with
		// no blocks); CPython 3.13's json.loads stops at 9997.
		hostileCase{"deep-nesting-498", k(fm, "", obj(`"x":`+nest(498, "")))},
		hostileCase{"deep-nesting-499", k(fm, "", obj(`"x":`+nest(499, "")))},
		hostileCase{"deep-number-leaf-498", k(fm, "", obj(`"x":`+nest(497, "0")))},
		hostileCase{"deep-number-leaf-499", k(fm, "", obj(`"x":`+nest(498, "0")))},
		hostileCase{"deep-string-leaf-499", k(fm, "", obj(`"x":`+nest(498, `"s"`)))},
		hostileCase{"deep-empty-object-498", k(fm, "", obj(`"x":`+nest(497, "{}")))},
		hostileCase{"deep-object-key-499", k(fm, "", obj(`"x":`+nest(497, `{"k":"v"}`)))},
		hostileCase{"deep-in-payload-hash", k(fm, "", strings.Replace(obj(""), `"__H__"`, nest(499, ""), 1))},
		hostileCase{"lone-surrogate-before-deep", k(fm, "", obj(`"a":"\ud800","x":`+nest(499, "")))},
		hostileCase{"deep-before-lone-surrogate", k(fm, "", obj(`"x":`+nest(499, "")+`,"a":"\ud800"`))},
		hostileCase{"deep-and-dup-key", k(fm, "", obj(`"x":`+nest(499, "")+`,"x":"1"`))},
		hostileCase{"deep-nesting-9997", k(fm, "", obj(`"x":`+nest(9997, "")))},
		hostileCase{"deep-nesting-9998", k(fm, "", obj(`"x":`+nest(9998, "")))},
		hostileCase{"deep-nesting-9998-then-dup-key", k(fm, "", obj(`"x":`+nest(9998, "")+`,"x":"1"`))},
		hostileCase{"file-not-utf8", append([]byte(fm), 0xc3, 0x28)},
		hostileCase{"file-empty", []byte{}},
	)
	return cases
}

// nest wraps inner in n JSON arrays.
func nest(n int, inner string) string {
	return strings.Repeat("[", n) + inner + strings.Repeat("]", n)
}

// flipTrailingBits sets unused low bits in the last data character before
// padding (CPython accepts these; a strict canonical decoder would not).
func flipTrailingBits(b string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	pad := len(b) - len(strings.TrimRight(b, "="))
	if pad == 0 {
		panic("need padded input to have spare bits")
	}
	i := len(b) - pad - 1
	v := strings.IndexByte(alphabet, b[i])
	return b[:i] + string(alphabet[v|1]) + b[i+1:]
}

func TestHostileBatteryMatchesLens(t *testing.T) {
	requirePython(t)
	protocolDir(t)
	dir := t.TempDir()
	cases := hostileCases(t)
	t.Logf("python3 is %s", pythonVersion())
	compared := 0
	for _, c := range cases {
		if skipOnThisPython(t, c.name) {
			continue
		}
		compared++
		path := filepath.Join(dir, c.name+".knobe.md")
		if err := os.WriteFile(path, c.data, 0o644); err != nil {
			t.Fatal(err)
		}
		py, ok := lens(t, path)
		if !ok {
			t.Errorf("%s: lens.py produced no JSON report", c.name)
			continue
		}
		if got := ours(t, path); got != py {
			t.Errorf("%s\n  lens: %+v\n  ours: %+v", c.name, py, got)
		}
	}
	t.Logf("compared %d of %d hostile cases", compared, len(cases))
}

// fullJSONExceptions are files whose complete --json output differs from
// lens.py by design, with the reason.
var fullJSONExceptions = map[string]string{
	// lens.py appends Python's codec error ("'utf-8' codec can't decode byte
	// 0xc3 in position 39: ..."); knobe-go reports the fact without the detail.
	"file-not-utf8": "reason text",
}

// The gate fields above are what upstream's harness compares. This goes
// further: the complete --json document, including every conformance issue
// and the unreadable reason, must be byte-identical to lens.py's, so a
// change to upstream's wording or check order fails here too.
func TestFullJSONMatchesLens(t *testing.T) {
	requirePython(t)
	dir := t.TempDir()
	var files []string
	for _, c := range hostileCases(t) {
		if skipOnThisPython(t, c.name) {
			continue
		}
		path := filepath.Join(dir, c.name+".knobe.md")
		if err := os.WriteFile(path, c.data, 0o644); err != nil {
			t.Fatal(err)
		}
		files = append(files, path)
	}
	files = append(files, corpus(t)...)
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".knobe.md")
		out, _ := exec.Command("python3", filepath.Join(protocolDir(t), "lens.py"), "--json", f).Output()
		want, got := strings.TrimSuffix(string(out), "\n"), VerifyFile(f).JSON()
		_, excepted := fullJSONExceptions[name]
		if (want == got) == excepted {
			t.Errorf("%s (exception listed: %v)\n--- lens.py\n%s\n--- ours\n%s", name, excepted, want, got)
		}
	}
	t.Logf("compared %d files", len(files))
}

// On the published files (which carry no crafted escapes) the human report
// is byte-identical to lens.py's too.
func TestHumanOutputMatchesLensOnPublishedFiles(t *testing.T) {
	requirePython(t)
	for _, f := range corpus(t) {
		out, _ := exec.Command("python3", filepath.Join(protocolDir(t), "lens.py"), f).Output()
		var b strings.Builder
		VerifyFile(f).WriteHuman(&b)
		if string(out) != b.String() {
			t.Errorf("%s\n--- lens.py\n%s--- ours\n%s", f, out, b.String())
		}
	}
}

// Sanity check that the battery exercises every status.
func TestHostileBatteryCoversEveryStatus(t *testing.T) {
	requirePython(t)
	protocolDir(t)
	seen := map[Status]int{}
	for _, c := range hostileCases(t) {
		seen[VerifyBytes(c.data).Status]++
	}
	for _, s := range []Status{Verified, VerifiedBodyModified, Failed, Unreadable} {
		if seen[s] == 0 {
			t.Errorf("no hostile case produces %s (%s)", s, fmt.Sprint(seen))
		}
	}
}
