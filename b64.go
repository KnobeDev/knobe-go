package knobe

// decodeBlock decodes a payload block as lens.py does:
// base64.b64decode("".join(block.split()), validate=True). Python whitespace
// is removed first; what remains must be strict, padded standard Base64
// (RFC 4648 §4; ERRATA E7). Like CPython, non-zero unused trailing bits are
// accepted. ok is false when the block is not decodable.
func decodeBlock(block string) ([]byte, bool) {
	clean := make([]byte, 0, len(block))
	for _, r := range block {
		if isPySpace(r) {
			continue
		}
		if r >= 0x80 {
			return nil, false
		}
		clean = append(clean, byte(r))
	}
	if len(clean)%4 != 0 {
		return nil, false
	}
	pad := 0
	for pad < len(clean) && clean[len(clean)-1-pad] == '=' {
		pad++
	}
	if pad > 2 {
		return nil, false
	}
	out := make([]byte, 0, len(clean)/4*3)
	var acc, bits uint32
	for _, c := range clean[:len(clean)-pad] {
		v, ok := sextet(c)
		if !ok {
			return nil, false
		}
		acc = acc<<6 | v
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
			acc &= 1<<bits - 1
		}
	}
	return out, true
}

func sextet(c byte) (uint32, bool) {
	switch {
	case c >= 'A' && c <= 'Z':
		return uint32(c - 'A'), true
	case c >= 'a' && c <= 'z':
		return uint32(c-'a') + 26, true
	case c >= '0' && c <= '9':
		return uint32(c-'0') + 52, true
	case c == '+':
		return 62, true
	case c == '/':
		return 63, true
	}
	return 0, false
}
