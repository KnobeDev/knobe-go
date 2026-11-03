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

// pyPrintable approximates Python str.isprintable() for repr(). It only
// shapes message text; nothing is hashed or gated on it.
func pyPrintable(r rune) bool {
	switch {
	case r <= 0x1F, r >= 0x7F && r <= 0xA0, r == 0xAD, r == 0x1680:
		return false
	case r >= 0x2000 && r <= 0x200F, r >= 0x2028 && r <= 0x202F, r >= 0x205F && r <= 0x2064:
		return false
	case r == 0x3000, r >= 0xD800 && r <= 0xDFFF, isFormatControl(r):
		return false
	}
	return true
}

// isFormatControl reports Unicode category Cf (bidi overrides and isolates,
// zero-width characters, U+FEFF) and the line/paragraph separators.
func isFormatControl(r rune) bool {
	return unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029
}

// reprStr is Python repr(str).
func reprStr(s string) string {
	quote := '\''
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		quote = '"'
	}
	var b strings.Builder
	b.WriteRune(quote)
	for _, r := range decodeRunes(s) {
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
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	b.WriteRune(quote)
	return b.String()
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

// SafeString is lens.py safe() for a string: escape C0/C1 controls and DEL as
// \xNN so a crafted string cannot spoof the report or inject terminal escape
// sequences, then truncate to limit code points (limit <= 0: no limit).
// Stricter than lens.py, it also escapes bidi overrides, isolates and
// zero-width characters (\uNNNN), which could reorder or hide report text.
func SafeString(s string, limit int) string {
	var b strings.Builder
	for _, r := range decodeRunes(s) {
		switch {
		case r < 0x20 || r == 0x7F || (r >= 0x80 && r <= 0x9F):
			fmt.Fprintf(&b, `\x%02x`, r)
		case isFormatControl(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	if limit > 0 && utf8.RuneCountInString(out) > limit {
		runes := []rune(out)
		out = string(runes[:limit]) + "…"
	}
	return out
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
