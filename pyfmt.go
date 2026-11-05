package knobe

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Python-compatible text behavior that the reference verifier (lens.py)
// depends on: str.isspace()/strip(), float repr(), repr() of values,
// truthiness, and lens.py's safe() terminal-escaping helper.

// isPySpace is Python str.isspace(): bidi WS/B/S or category Zs. This is the
// set str.split(), str.strip() and regex \s use in lens.py.
func isPySpace(r rune) bool {
	switch {
	case r == '\t' || r == '\n' || r == '\v' || r == '\f' || r == '\r' || r == ' ':
		return true
	case r >= 0x1C && r <= 0x1F, r == 0x85, r == 0xA0, r == 0x1680:
		return true
	case r >= 0x2000 && r <= 0x200A, r == 0x2028, r == 0x2029, r == 0x202F, r == 0x205F, r == 0x3000:
		return true
	}
	return false
}

// pyStrip is Python s.strip() with no arguments.
func pyStrip(s string) string { return strings.TrimFunc(s, isPySpace) }

// floatRepr is Python repr(float), which json.dumps emits: shortest
// round-trip digits; fixed notation when the decimal exponent is in
// [-4, 16), with at least one fractional digit; otherwise d[.ddd]e±XX.
// ok is false for ±Inf/NaN, which json.dumps(allow_nan=False) refuses.
func floatRepr(x float64) (string, bool) {
	if x != x || x > maxFloat || x < -maxFloat {
		return "", false
	}
	if x == 0 {
		if 1/x < 0 {
			return "-0.0", true
		}
		return "0.0", true
	}
	e := strconv.FormatFloat(x, 'e', -1, 64) // e.g. "-1.5e+22", "5e-324"
	mant, expStr, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expStr)
	sign := ""
	if strings.HasPrefix(mant, "-") {
		sign, mant = "-", mant[1:]
	}
	digits := strings.Replace(mant, ".", "", 1)

	if exp < -4 || exp >= 16 {
		m := digits
		if len(digits) > 1 {
			m = digits[:1] + "." + digits[1:]
		}
		esign := "+"
		if exp < 0 {
			esign, exp = "-", -exp
		}
		return fmt.Sprintf("%s%se%s%02d", sign, m, esign, exp), true
	}
	var out string
	switch intLen := exp + 1; {
	case exp < 0:
		out = "0." + strings.Repeat("0", -exp-1) + digits
	case intLen >= len(digits):
		out = digits + strings.Repeat("0", intLen-len(digits)) + ".0"
	default:
		out = digits[:intLen] + "." + digits[intLen:]
	}
	return sign + out, true
}

const maxFloat = 1.7976931348623157e308

// intRepr is Python str(int) of a JSON integer lexeme: identical except that
// negative zero ("-0", "-00" cannot occur in JSON) prints as "0".
func intRepr(lexeme string) string {
	if lexeme == "-0" {
		return "0"
	}
	return lexeme
}

// typeName is the Python type name of a parsed JSON value, for messages.
func typeName(v Value) string {
	switch v.Kind {
	case Null:
		return "NoneType"
	case Bool:
		return "bool"
	case Int:
		return "int"
	case Float:
		return "float"
	case String:
		return "str"
	case Array:
		return "list"
	}
	return "dict"
}

// truthy is Python truthiness.
func truthy(v Value) bool {
	switch v.Kind {
	case Null:
		return false
	case Bool:
		return v.B
	case Int:
		return intRepr(v.Num) != "0"
	case Float:
		return v.F != 0
	case String:
		return v.S != ""
	case Array:
		return len(v.Arr) > 0
	}
	return len(v.Obj) > 0
}

// pyPrintable is Python str.isprintable() for one code point: false for
// categories Cc, Cf, Cs, Co, Cn (unassigned), Zl, Zp and Zs other than the
// space. Python 3.13 uses Unicode 15.1 and Go 1.22 Unicode 15.0; the code
// points 15.1 added are counted as assigned here.
func pyPrintable(r rune) bool {
	switch {
	case r == ' ':
		return true
	case r >= 0xD800 && r <= 0xDFFF:
		return false
	case unicode.In(r, unicode.Cc, unicode.Cf, unicode.Co, unicode.Zs, unicode.Zl, unicode.Zp):
		return false
	}
	return unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S) || addedInUnicode151(r)
}

// addedInUnicode151 reports the code points Unicode 15.1 assigned: the
// ideographic description characters U+2FFC-2FFF and U+31EF (So) and CJK
// Extension I (Lo).
func addedInUnicode151(r rune) bool {
	return (r >= 0x2FFC && r <= 0x2FFF) || r == 0x31EF || (r >= 0x2EBF0 && r <= 0x2EE5D)
}

// reprStr is Python repr(str).
func reprStr(s string) string { return reprRunes(decodeRunes(s)) }

// reprRunes is Python repr() of the string made of runes, which may include
// lone surrogates.
func reprRunes(rs []rune) string {
	quote := '\''
	if containsRune(rs, '\'') && !containsRune(rs, '"') {
		quote = '"'
	}
	var b strings.Builder
	b.WriteRune(quote)
	for _, r := range rs {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == quote:
			b.WriteRune('\\')
			b.WriteRune(r)
		case pyPrintable(r):
			b.WriteRune(r)
		case r <= 0xFF:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r <= 0xFFFF:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	b.WriteRune(quote)
	return b.String()
}

func containsRune(rs []rune, r rune) bool {
	for _, x := range rs {
		if x == r {
			return true
		}
	}
	return false
}

// pyStr is Python str() of a parsed JSON value: a string as is, anything
// else as its repr().
func pyStr(v Value) string {
	if v.Kind == String {
		return v.S
	}
	return repr(v)
}

// repr is Python repr() of a parsed JSON value.
func repr(v Value) string {
	switch v.Kind {
	case Null:
		return "None"
	case Bool:
		if v.B {
			return "True"
		}
		return "False"
	case Int:
		return intRepr(v.Num)
	case Float:
		if s, ok := floatRepr(v.F); ok {
			return s
		}
		if v.F < 0 {
			return "-inf"
		}
		return "inf"
	case String:
		return reprStr(v.S)
	case Array:
		parts := make([]string, len(v.Arr))
		for i, item := range v.Arr {
			parts[i] = repr(item)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	parts := make([]string, len(v.Obj))
	for i, m := range v.Obj {
		parts[i] = reprStr(m.Key) + ": " + repr(m.Val)
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// SafeString is lens.py safe() for a string, so a crafted string cannot
// spoof the report, inject terminal escape sequences or visually reorder
// text. It escapes C0 and C1 controls and DEL as \xNN; bidi embeddings,
// overrides and isolates (U+202A-202E, U+2066-2069), the line and paragraph
// separators (U+2028, U+2029) and unpaired surrogates as \uNNNN; and keeps
// everything else, backslashes included. The result is then cut to limit
// code points plus "…" (limit <= 0: no limit). An unpaired surrogate is
// read from its WTF-8 form, as the JSON parser keeps it.
func SafeString(s string, limit int) string { return safeRunes(decodeRunes(s), limit) }

func safeRunes(rs []rune, limit int) string {
	var b strings.Builder
	n := 0
	for _, r := range rs {
		if limit > 0 && n == limit {
			b.WriteString("…")
			return b.String()
		}
		switch {
		case r < 0x20 || r == 0x7F || (r >= 0x80 && r <= 0x9F):
			fmt.Fprintf(&b, `\x%02x`, r)
			n += 4
		case (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) ||
			r == 0x2028 || r == 0x2029 || (r >= 0xD800 && r <= 0xDFFF):
			fmt.Fprintf(&b, `\u%04x`, r)
			n += 6
		default:
			b.WriteRune(r)
			n++
		}
		if limit > 0 && n > limit {
			// The escape crossed the limit: keep its first code points only.
			out := []rune(b.String())
			return string(out[:limit]) + "…"
		}
	}
	return b.String()
}

// safe is lens.py safe() for any value: strings escaped and truncated,
// everything else repr() (which escapes non-printables itself).
func safe(v Value) string {
	if v.Kind == String {
		return SafeString(v.S, 300)
	}
	return repr(v)
}

// decodeRunes decodes s like UTF-8, but reads a WTF-8 surrogate (an unpaired
// \uD800-\uDFFF escape kept by the JSON parser) as its code point instead of
// three U+FFFD, matching how Python sees such a string.
func decodeRunes(s string) []rune {
	out := make([]rune, 0, len(s))
	for i := 0; i < len(s); {
		if i+2 < len(s) && s[i] == 0xED && s[i+1] >= 0xA0 && s[i+1] <= 0xBF && s[i+2]&0xC0 == 0x80 {
			out = append(out, rune(s[i]&0x0F)<<12|rune(s[i+1]&0x3F)<<6|rune(s[i+2]&0x3F))
			i += 3
			continue
		}
		r, n := utf8.DecodeRuneInString(s[i:])
		out = append(out, r)
		i += n
	}
	return out
}
