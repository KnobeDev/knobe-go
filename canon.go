package knobe

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// Spec §5 canonical form and hashes, FROZEN for v1.
//
// payload_hash = SHA-256 of: the payload minus `payload_hash`, every object
// key and string value NFC-normalized, serialized with keys recursively
// sorted by code point, no whitespace, arrays in order, literal UTF-8
// (\uXXXX only for C0 controls), numbers as Python repr.
//
// body_hash = SHA-256 of the body after: Python strip() of the whole body,
// CRLF and lone CR to LF, only U+0020/U+0009 stripped from each line end, no
// Unicode normalization.

// errNonFinite marks a float that overflowed to ±Inf: it has no canonical form.
var errNonFinite = errors.New("number overflows to infinity")

func nfc(s string) string { return norm.NFC.String(s) }

// nfcValue recursively NFC-normalizes object keys and string values.
func nfcValue(v Value) Value {
	switch v.Kind {
	case String:
		return Value{Kind: String, S: nfc(v.S)}
	case Array:
		arr := make([]Value, len(v.Arr))
		for i, item := range v.Arr {
			arr[i] = nfcValue(item)
		}
		return Value{Kind: Array, Arr: arr}
	case Object:
		obj := make([]Member, len(v.Obj))
		for i, m := range v.Obj {
			obj[i] = Member{Key: nfc(m.Key), Val: nfcValue(m.Val)}
		}
		return Value{Kind: Object, Obj: obj}
	}
	return v
}

// canonical serializes an already NFC-normalized value. Keys sort by UTF-8
// bytes, which is code-point order (Python's str order, not UTF-16 order).
func canonical(v Value) (string, error) {
	var b strings.Builder
	if err := writeCanonical(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

func writeCanonical(b *strings.Builder, v Value) error {
	switch v.Kind {
	case Null:
		b.WriteString("null")
	case Bool:
		if v.B {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case Int, Float:
		s, ok := numberRepr(v)
		if !ok {
			return errNonFinite
		}
		b.WriteString(s)
	case String:
		writeJSONString(b, v.S)
	case Array:
		b.WriteByte('[')
		for i, item := range v.Arr {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, item); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case Object:
		members := append([]Member(nil), v.Obj...)
		sort.Slice(members, func(i, j int) bool { return members[i].Key < members[j].Key })
		b.WriteByte('{')
		for i, m := range members {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSONString(b, m.Key)
			b.WriteByte(':')
			if err := writeCanonical(b, m.Val); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	}
	return nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// PayloadHash is the §5 payload hash of a payload object; its own
// payload_hash member is ignored.
func PayloadHash(payload Value) (string, error) {
	without := payload
	if payload.Kind == Object {
		without = Value{Kind: Object}
		for _, m := range payload.Obj {
			if m.Key != "payload_hash" {
				without.Obj = append(without.Obj, m)
			}
		}
	}
	c, err := canonical(nfcValue(without))
	if err != nil {
		return "", err
	}
	return sha256Hex(c), nil
}

// NormalizeBody applies the §6 body normalization.
func NormalizeBody(text string) string {
	t := pyStrip(text)
	t = strings.ReplaceAll(t, "\r\n", "\n")
	t = strings.ReplaceAll(t, "\r", "\n")
	lines := strings.Split(t, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}
	return strings.Join(lines, "\n")
}

// BodyHash is the §6 body hash.
func BodyHash(text string) string { return sha256Hex(NormalizeBody(text)) }
