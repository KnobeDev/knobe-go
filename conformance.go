package knobe

import (
	"fmt"
	"strings"
)

// Schema/spec conformance, following lens.py check_conformance. Errors make
// a file invalid; soft deviations alone make it warnings.

// stringFields are required fields that MUST be JSON strings (spec §4).
var stringFields = []string{
	"spec_version", "title", "summary", "content_type", "created_date",
	"license", "privacy_level", "quarantine_status",
}

// canonicalVocab lists the spec §8 vocabularies. A custom value without an
// `ext-` or `domain:` prefix is a warning, not an error.
var canonicalVocab = []struct {
	field  string
	values []string
}{
	{"content_type", []string{"original", "synthesis", "adaptation", "compression", "annotation", "seed", "collection", "translation"}},
	{"quarantine_status", []string{"quarantine", "trusted", "rejected"}},
	{"privacy_level", []string{"public", "internal", "sensitive", "restricted"}},
	{"identity_status", []string{"declared", "signed"}},
}

func checkConformance(p Value, missing []string, fm frontmatter, blockCount int) (Conformance, []string) {
	var errs, warns []string

	// 1. Frontmatter presence; a spec_version disagreeing with the sealed
	//    payload is a warning, the sealed value is authoritative (ERRATA E5).
	if !fm.ok {
		errs = append(errs, "YAML frontmatter missing or malformed: "+fm.reason)
	} else if ps, isStr := strField(p, "spec_version"); fm.hasSpec && isStr && fm.spec != ps {
		warns = append(warns, fmt.Sprintf("frontmatter spec_version %s does not match sealed payload spec_version %s",
			reprStr(fm.spec), reprStr(ps)))
	}

	// 2. Missing required fields (ERRATA E9: absent attribution is one issue).
	for _, m := range missing {
		errs = append(errs, "required field missing: "+m)
	}

	// 3. Required-field types (spec §4).
	for _, f := range stringFields {
		if v, ok := p.Get(f); ok && v.Kind != String {
			errs = append(errs, fmt.Sprintf("required field %s must be a string, got %s", f, typeName(v)))
		}
	}

	// 4. attribution: an object whose sources, if present, is a non-empty array.
	if att, ok := p.Get("attribution"); ok && att.Kind != Null {
		if att.Kind != Object {
			errs = append(errs, "attribution must be an object, got "+typeName(att))
		} else if src, ok := att.Get("sources"); ok && src.Kind != Null {
			switch {
			case src.Kind != Array:
				errs = append(errs, "attribution.sources must be an array, got "+typeName(src))
			case len(src.Arr) == 0:
				errs = append(errs, "attribution.sources must be a non-empty array")
			}
		}
	}

	// 5-6. Hash formats (spec §4). JSON null counts as absent, as in lens.py.
	for _, f := range []string{"payload_hash", "body_hash"} {
		if v, ok := p.Get(f); ok && v.Kind != Null && !hex64(v) {
			errs = append(errs, f+" format invalid (must be 64 lowercase hex)")
		}
	}

	// 7. created_date: YYYY-MM-DD shape and a real calendar date (spec §4).
	if cd, ok := p.Get("created_date"); ok && cd.Kind != Null {
		if s, isStr := cd.Str(); !isStr || !isoDateShape(s) {
			errs = append(errs, "created_date is not in YYYY-MM-DD form: "+repr(cd))
		} else if !isRealISODate(s) {
			errs = append(errs, "created_date is not a real calendar date: "+reprStr(s))
		}
	}

	// 8. Bare numbers anywhere but payload_hash itself (spec §5).
	var paths []string
	for _, m := range p.Obj {
		if m.Key != "payload_hash" {
			numericPaths(m.Val, m.Key, &paths)
		}
	}
	if len(paths) > 0 {
		if len(paths) > 5 {
			paths = append(paths[:5], "...")
		}
		errs = append(errs, "bare numeric value(s) in payload (spec §5 requires strings): "+strings.Join(paths, ", "))
	}

	// 9. parents[i].payload_hash format, when parents is a list.
	if parents, ok := p.Get("parents"); ok && parents.Kind == Array {
		for i, parent := range parents.Arr {
			if h, ok := parent.Get("payload_hash"); ok && !hex64(h) {
				errs = append(errs, fmt.Sprintf("parents[%d].payload_hash format invalid (must be 64 lowercase hex)", i))
			}
		}
	}

	// 10. Multiple payload blocks (spec §3.3).
	if blockCount > 1 {
		warns = append(warns, fmt.Sprintf("multiple payload blocks present (%d); evaluated the last block per spec §3.3", blockCount))
	}

	// 11. Custom vocabulary without a namespace prefix (spec §8).
	for _, voc := range canonicalVocab {
		v, isStr := strField(p, voc.field)
		if isStr && !contains(voc.values, v) && !strings.Contains(v, ":") && !strings.HasPrefix(v, "ext-") {
			warns = append(warns, fmt.Sprintf("%s: %s is a custom vocabulary value without namespace prefix "+
				"(recommend 'ext-' or 'domain:' per §8)", voc.field, reprStr(v)))
		}
	}

	switch {
	case len(errs) > 0:
		return Invalid, append(errs, warns...)
	case len(warns) > 0:
		return Warnings, warns
	}
	return Valid, []string{}
}

func strField(p Value, key string) (string, bool) {
	v, ok := p.Get(key)
	if !ok {
		return "", false
	}
	return v.Str()
}

// hex64 is lens.py HEX64 (^[0-9a-f]{64}\Z): exactly 64 lowercase ASCII hex
// characters with nothing after them, not even a newline (ERRATA E12).
func hex64(v Value) bool {
	s, ok := v.Str()
	if !ok || len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// isoDateShape is lens.py ISO_DATE (^[0-9]{4}-[0-9]{2}-[0-9]{2}\Z): exactly
// ten ASCII characters with nothing after them (ERRATA E12).
func isoDateShape(s string) bool {
	if len(s) != 10 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if i == 4 || i == 7 {
			if s[i] != '-' {
				return false
			}
		} else if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isRealISODate is datetime.date.fromisoformat on a string that already has
// the date shape: ASCII YYYY-MM-DD, year 1-9999, a real calendar day.
func isRealISODate(s string) bool {
	if len(s) != 10 || s[4] != '-' || s[7] != '-' {
		return false
	}
	num := func(part string) (int, bool) {
		n := 0
		for i := 0; i < len(part); i++ {
			if part[i] < '0' || part[i] > '9' {
				return 0, false
			}
			n = n*10 + int(part[i]-'0')
		}
		return n, true
	}
	y, ok1 := num(s[0:4])
	m, ok2 := num(s[5:7])
	d, ok3 := num(s[8:10])
	if !ok1 || !ok2 || !ok3 || y < 1 {
		return false
	}
	days := 31
	switch m {
	case 4, 6, 9, 11:
		days = 30
	case 2:
		days = 28
		if (y%4 == 0 && y%100 != 0) || y%400 == 0 {
			days = 29
		}
	case 1, 3, 5, 7, 8, 10, 12:
	default:
		return false
	}
	return d >= 1 && d <= days
}

// numericPaths appends the paths of bare numbers in v, in payload order.
func numericPaths(v Value, path string, out *[]string) {
	switch v.Kind {
	case Int, Float:
		*out = append(*out, path)
	case Object:
		for _, m := range v.Obj {
			next := m.Key
			if path != "" {
				next = path + "." + m.Key
			}
			numericPaths(m.Val, next, out)
		}
	case Array:
		for i, item := range v.Arr {
			numericPaths(item, fmt.Sprintf("%s[%d]", path, i), out)
		}
	}
}
