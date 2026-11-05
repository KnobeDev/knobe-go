package knobe

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
)

// How Python presents file names and decoding errors, for the reasons
// lens.py gives when it cannot read a file.

// pyPath is a command-line path as Python holds it: UTF-8 decoded with the
// surrogateescape error handler, so each byte that is not part of a valid
// UTF-8 sequence becomes the lone surrogate U+DC80-U+DCFF.
func pyPath(path string) []rune {
	out := make([]rune, 0, len(path))
	for i := 0; i < len(path); {
		r, n := utf8.DecodeRuneInString(path[i:])
		if r == utf8.RuneError && n == 1 {
			r = 0xDC00 + rune(path[i])
		}
		out = append(out, r)
		i += n
	}
	return out
}

// safePath is lens.py safe(path, None) of a command-line path.
func safePath(path string) string { return safeRunes(pyPath(path), 0) }

// readErrorReason words a file error as lens.py verify() does.
func readErrorReason(path string, err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "file not found: " + safePath(path)
	case errors.Is(err, syscall.EISDIR):
		return "path is a directory, not a file: " + safePath(path)
	}
	return "could not read file: " + osErrorText(path, err)
}

// osErrorText is Python str(OSError) for a failure to open or read path:
// "[Errno N] <strerror>: <repr(path)>" when open() failed, and
// "[Errno N] <strerror>" when a later read failed (Python's read() error
// carries no file name).
func osErrorText(path string, err error) string {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		// Not a system error: no Python equivalent. Escape it, since it may
		// carry the raw path.
		return SafeString(err.Error(), 0)
	}
	text := fmt.Sprintf("[Errno %d] %s", int(errno), strerror(errno))
	var pe *fs.PathError
	if errors.As(err, &pe) && pe.Op != "open" {
		return text
	}
	return text + ": " + reprRunes(pyPath(path))
}

// strerror is the C library's message for errno, as Python shows it. On
// Linux that is glibc's: Go's own text with a capital first letter, except
// for the few errnos listed here (checked against os.strerror on glibc).
func strerror(errno syscall.Errno) string {
	switch int(errno) {
	case 116:
		return "Stale file handle"
	case 133:
		return "Memory page has hardware error"
	}
	msg := errno.Error()
	if strings.HasPrefix(msg, "errno ") {
		return fmt.Sprintf("Unknown error %d", int(errno))
	}
	r, n := utf8.DecodeRuneInString(msg)
	return string(unicode.ToUpper(r)) + msg[n:]
}

// utf8ErrorText is Python str(UnicodeDecodeError) for data.decode("utf-8"),
// or "" when data is valid UTF-8. CPython reports the first invalid
// sequence: if the input ends inside an otherwise valid sequence, the rest
// of the input, "unexpected end of data"; otherwise the maximal valid prefix
// of that sequence (at least one byte), "invalid continuation byte" after a
// lead byte (0xC2-0xF4) and "invalid start byte" otherwise.
func utf8ErrorText(data []byte) string {
	start := 0
	for start < len(data) {
		r, n := utf8.DecodeRune(data[start:])
		if r == utf8.RuneError && n == 1 {
			break
		}
		start += n
	}
	if start == len(data) {
		return ""
	}
	span, atEnd := invalidSpan(data[start:])
	why := "invalid start byte"
	switch {
	case atEnd:
		why = "unexpected end of data"
	case data[start] >= 0xC2 && data[start] <= 0xF4:
		why = "invalid continuation byte"
	}
	if span == 1 {
		return fmt.Sprintf("'utf-8' codec can't decode byte 0x%02x in position %d: %s", data[start], start, why)
	}
	return fmt.Sprintf("'utf-8' codec can't decode bytes in position %d-%d: %s", start, start+span-1, why)
}

// invalidSpan measures the invalid sequence at the start of b: the length of
// its maximal valid prefix (at least 1), or, when b ends inside a sequence
// that is valid so far, len(b) and atEnd.
func invalidSpan(b []byte) (span int, atEnd bool) {
	lo, hi := byte(0x80), byte(0xBF) // allowed range of the second byte
	width := 0
	switch c := b[0]; {
	case c >= 0xC2 && c <= 0xDF:
		width = 2
	case c == 0xE0:
		width, lo = 3, 0xA0
	case c == 0xED:
		width, hi = 3, 0x9F // no encoded surrogates
	case c >= 0xE1 && c <= 0xEF:
		width = 3
	case c == 0xF0:
		width, lo = 4, 0x90
	case c >= 0xF1 && c <= 0xF3:
		width = 4
	case c == 0xF4:
		width, hi = 4, 0x8F
	default:
		return 1, false
	}
	for i := 1; i < width; i++ {
		if i >= len(b) {
			return len(b), true
		}
		if i > 1 {
			lo, hi = 0x80, 0xBF
		}
		if b[i] < lo || b[i] > hi {
			return i, false
		}
	}
	return width, false // unreachable for an invalid sequence
}
