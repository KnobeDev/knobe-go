package knobe

import (
	"fmt"
	"strconv"
	"strings"
)

// Kind is the JSON type of a Value.
type Kind int

const (
	Null Kind = iota
	Bool
	Int   // integer lexeme kept exactly as written (arbitrary precision, like Python int)
	Float // float64, parsed with correct rounding like Python float()
	String
	Array
	Object
)

// Value is a parsed JSON value. Objects keep insertion order; the parser
// guarantees their keys are unique.
type Value struct {
	Kind Kind
	B    bool
	Num  string // Int lexeme
	F    float64
	S    string
	Arr  []Value
	Obj  []Member
}

// Member is one key/value pair of an Object.
type Member struct {
	Key string
	Val Value
}

// Get returns the value of key in an Object.
func (v Value) Get(key string) (Value, bool) {
	if v.Kind != Object {
		return Value{}, false
	}
	for _, m := range v.Obj {
		if m.Key == key {
			return m.Val, true
		}
	}
	return Value{}, false
}

// Has reports whether an Object contains key.
func (v Value) Has(key string) bool {
	_, ok := v.Get(key)
	return ok
}

// Str returns the string value and whether v is a String.
func (v Value) Str() (string, bool) {
	return v.S, v.Kind == String
}

// ParseError kinds, so the verifier can word its unreadable reason as lens.py does.
type ParseError struct {
	DuplicateKey string
	IsDuplicate  bool
	NonJSONConst bool
	Msg          string
	Offset       int
}

func (e *ParseError) Error() string {
	switch {
	case e.IsDuplicate:
		return "duplicate JSON key: " + e.DuplicateKey
	case e.NonJSONConst:
		return "non-JSON numeric constant (NaN/Infinity)"
	default:
		return fmt.Sprintf("%s at byte %d", e.Msg, e.Offset)
	}
}

// maxDepth bounds nesting so hostile input fails cleanly (the verifier then
// reports the file unreadable). 996 is the deepest nesting lens.py reports
// on: a payload {"x":[[...]]} with 996 nested arrays verifies there, and one
// more level exhausts CPython's recursion limit inside lens.py's
// conformance helpers, which crash instead of producing a report.
const maxDepth = 996

// maxIntDigits is CPython's default int max_str_digits: json.loads refuses a
// longer integer literal, so lens.py reports such a payload unreadable.
const maxIntDigits = 4300

// ParseResult carries the parsed value plus a flag for unpaired UTF-16
// surrogate escapes. Python accepts those while parsing but cannot
// UTF-8-encode them, so the verifier rejects the payload after its
// structural checks, as lens.py does.
type ParseResult struct {
	Value         Value
	LoneSurrogate bool
}

// ParseJSON parses one strict RFC 8259 document. Duplicate keys at any depth
// and NaN/Infinity are errors. Only JSON whitespace may surround the value.
func ParseJSON(text string) (ParseResult, error) {
	p := &parser{s: text}
	v, err := p.value(0)
	if err != nil {
		return ParseResult{}, err
	}
	p.ws()
	if p.i != len(p.s) {
		return ParseResult{}, p.err("trailing content")
	}
	return ParseResult{Value: v, LoneSurrogate: p.loneSurrogate}, nil
}

type parser struct {
	s             string
	i             int
	loneSurrogate bool
}

func (p *parser) err(msg string) error { return &ParseError{Msg: msg, Offset: p.i} }

func (p *parser) peek() (byte, bool) {
	if p.i < len(p.s) {
		return p.s[p.i], true
	}
	return 0, false
}

func (p *parser) ws() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) eat(lit string) bool {
	if strings.HasPrefix(p.s[p.i:], lit) {
		p.i += len(lit)
		return true
	}
	return false
}

func (p *parser) value(depth int) (Value, error) {
	if depth > maxDepth {
		return Value{}, p.err("nesting too deep")
	}
	p.ws()
	rest := p.s[p.i:]
	if strings.HasPrefix(rest, "NaN") || strings.HasPrefix(rest, "Infinity") || strings.HasPrefix(rest, "-Infinity") {
		return Value{}, &ParseError{NonJSONConst: true}
	}
	c, ok := p.peek()
	if !ok {
		return Value{}, p.err("unexpected end of input")
	}
	switch {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		s, err := p.str()
		return Value{Kind: String, S: s}, err
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	case p.eat("true"):
		return Value{Kind: Bool, B: true}, nil
	case p.eat("false"):
		return Value{Kind: Bool}, nil
	case p.eat("null"):
		return Value{Kind: Null}, nil
	}
	return Value{}, p.err("unexpected token")
}

func (p *parser) object(depth int) (Value, error) {
	p.i++
	out := Value{Kind: Object, Obj: []Member{}}
	// A map keeps duplicate detection linear on hostile input.
	seen := map[string]struct{}{}
	p.ws()
	if c, _ := p.peek(); c == '}' {
		p.i++
		return out, nil
	}
	for {
		p.ws()
		if c, _ := p.peek(); c != '"' {
			return Value{}, p.err("expected string key")
		}
		key, err := p.str()
		if err != nil {
			return Value{}, err
		}
		if _, dup := seen[key]; dup {
			return Value{}, &ParseError{IsDuplicate: true, DuplicateKey: key}
		}
		seen[key] = struct{}{}
		p.ws()
		if c, _ := p.peek(); c != ':' {
			return Value{}, p.err("expected ':'")
		}
		p.i++
		v, err := p.value(depth + 1)
		if err != nil {
			return Value{}, err
		}
		out.Obj = append(out.Obj, Member{Key: key, Val: v})
		p.ws()
		c, _ := p.peek()
		switch c {
		case ',':
			p.i++
		case '}':
			p.i++
			return out, nil
		default:
			return Value{}, p.err("expected ',' or '}'")
		}
	}
}

func (p *parser) array(depth int) (Value, error) {
	p.i++
	out := Value{Kind: Array, Arr: []Value{}}
	p.ws()
	if c, _ := p.peek(); c == ']' {
		p.i++
		return out, nil
	}
	for {
		v, err := p.value(depth + 1)
		if err != nil {
			return Value{}, err
		}
		out.Arr = append(out.Arr, v)
		p.ws()
		c, _ := p.peek()
		switch c {
		case ',':
			p.i++
		case ']':
			p.i++
			return out, nil
		default:
			return Value{}, p.err("expected ',' or ']'")
		}
	}
}

func (p *parser) hex4() (rune, error) {
	if p.i+4 > len(p.s) {
		return 0, p.err("invalid \\u escape")
	}
	var n rune
	for _, c := range []byte(p.s[p.i : p.i+4]) {
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, p.err("invalid \\u escape")
		}
		n = n<<4 | rune(d)
	}
	p.i += 4
	return n, nil
}

func (p *parser) str() (string, error) {
	p.i++ // opening quote
	var b strings.Builder
	for {
		start := p.i
		for p.i < len(p.s) {
			c := p.s[p.i]
			if c == '"' || c == '\\' || c < 0x20 {
				break
			}
			p.i++
		}
		b.WriteString(p.s[start:p.i])
		c, ok := p.peek()
		if !ok {
			return "", p.err("unterminated string")
		}
		switch {
		case c == '"':
			p.i++
			return b.String(), nil
		case c < 0x20:
			return "", p.err("control character in string")
		}
		// backslash escape
		p.i++
		e, ok := p.peek()
		if !ok {
			return "", p.err("unterminated string")
		}
		p.i++
		switch e {
		case '"':
			b.WriteByte('"')
		case '\\':
			b.WriteByte('\\')
		case '/':
			b.WriteByte('/')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'u':
			if err := p.unicodeEscape(&b); err != nil {
				return "", err
			}
		default:
			return "", p.err("invalid escape")
		}
	}
}

// unicodeEscape handles the text after `\u`: a BMP scalar, a surrogate pair,
// or (as Python allows) an unpaired surrogate. An unpaired surrogate is kept
// as its WTF-8 bytes so distinct keys stay distinct, and flagged: it has no
// UTF-8 encoding, so the payload cannot be canonicalized.
func (p *parser) unicodeEscape(b *strings.Builder) error {
	hi, err := p.hex4()
	if err != nil {
		return err
	}
	if hi >= 0xD800 && hi < 0xDC00 && strings.HasPrefix(p.s[p.i:], "\\u") {
		save := p.i
		p.i += 2
		lo, err := p.hex4()
		if err != nil {
			return err
		}
		if lo >= 0xDC00 && lo < 0xE000 {
			b.WriteRune(0x10000 + (hi-0xD800)<<10 + (lo - 0xDC00))
			return nil
		}
		p.i = save // the next escape is processed on its own, as Python does
	}
	if hi >= 0xD800 && hi < 0xE000 {
		p.loneSurrogate = true
		b.WriteString(wtf8(hi))
		return nil
	}
	b.WriteRune(hi)
	return nil
}

// wtf8 encodes a surrogate code point the way UTF-8 would if it were allowed.
func wtf8(r rune) string {
	return string([]byte{0xE0 | byte(r>>12), 0x80 | byte(r>>6)&0x3F, 0x80 | byte(r)&0x3F})
}

func (p *parser) digits() int {
	start := p.i
	for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
		p.i++
	}
	return p.i - start
}

func (p *parser) number() (Value, error) {
	start := p.i
	if p.s[p.i] == '-' {
		p.i++
	}
	c, ok := p.peek()
	switch {
	case ok && c == '0':
		p.i++
	case ok && c >= '1' && c <= '9':
		p.digits()
	default:
		return Value{}, p.err("invalid number")
	}
	isInt := true
	if c, _ := p.peek(); c == '.' {
		isInt = false
		p.i++
		if p.digits() == 0 {
			return Value{}, p.err("invalid number")
		}
	}
	if c, _ := p.peek(); c == 'e' || c == 'E' {
		isInt = false
		p.i++
		if c, _ := p.peek(); c == '+' || c == '-' {
			p.i++
		}
		if p.digits() == 0 {
			return Value{}, p.err("invalid number")
		}
	}
	lexeme := p.s[start:p.i]
	if isInt {
		if len(strings.TrimPrefix(lexeme, "-")) > maxIntDigits {
			return Value{}, p.err("integer literal exceeds Python's 4300-digit limit")
		}
		return Value{Kind: Int, Num: lexeme}, nil
	}
	// Correctly rounded like Python float(). Out of range yields ±Inf (with
	// ErrRange), which has no canonical form; the verifier rejects it later.
	f, err := strconv.ParseFloat(lexeme, 64)
	if err != nil && !isRangeErr(err) {
		return Value{}, p.err("invalid number")
	}
	return Value{Kind: Float, F: f}, nil
}

func isRangeErr(err error) bool {
	ne, ok := err.(*strconv.NumError)
	return ok && ne.Err == strconv.ErrRange
}

// writeJSONString writes s as Python json.dumps(..., ensure_ascii=False)
// does: `"` `\` and C0 controls escaped (short forms for \b \t \n \f \r,
// lowercase \u00xx otherwise); everything else literal UTF-8.
func writeJSONString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteString(`\t`)
		case c == '\b':
			b.WriteString(`\b`)
		case c == '\f':
			b.WriteString(`\f`)
		case c < 0x20:
			fmt.Fprintf(b, `\u%04x`, c)
		default:
			b.WriteByte(c)
		}
		i++
	}
	b.WriteByte('"')
}

// numberRepr is a JSON number as Python json.dumps writes it; ok is false
// for a float that overflowed to ±Inf.
func numberRepr(v Value) (string, bool) {
	if v.Kind == Int {
		return intRepr(v.Num), true
	}
	return floatRepr(v.F)
}

// prettyJSON is Python json.dumps(v, indent=2, ensure_ascii=False), used for
// the --json report.
func prettyJSON(v Value) string {
	var b strings.Builder
	pretty(&b, v, 0)
	return b.String()
}

func pretty(b *strings.Builder, v Value, level int) {
	pad := func(n int) string { return strings.Repeat("  ", n) }
	switch v.Kind {
	case Null:
		b.WriteString("null")
	case Bool:
		b.WriteString(strconv.FormatBool(v.B))
	case Int, Float:
		if s, ok := numberRepr(v); ok {
			b.WriteString(s)
		} else if v.F < 0 {
			b.WriteString("-Infinity")
		} else {
			b.WriteString("Infinity")
		}
	case String:
		writeJSONString(b, v.S)
	case Array:
		if len(v.Arr) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteByte('[')
		for i, item := range v.Arr {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString("\n" + pad(level+1))
			pretty(b, item, level+1)
		}
		b.WriteString("\n" + pad(level) + "]")
	case Object:
		if len(v.Obj) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteByte('{')
		for i, m := range v.Obj {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString("\n" + pad(level+1))
			writeJSONString(b, m.Key)
			b.WriteString(": ")
			pretty(b, m.Val, level+1)
		}
		b.WriteString("\n" + pad(level) + "}")
	}
}
