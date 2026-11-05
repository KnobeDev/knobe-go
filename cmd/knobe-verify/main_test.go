package main

import (
	"io"
	"strings"
	"testing"

	knobe "github.com/KnobeDev/knobe-go"
)

func TestVerifySafelyReportsPanicAsUnreadable(t *testing.T) {
	var stderr strings.Builder
	r := verifySafely(func(string) knobe.Report { panic("boom\x1b[2J") }, "x.knobe.md", &stderr)
	if r.Status != knobe.Unreadable || r.Conformance != knobe.Invalid || r.ExitCode() != 2 || r.Reason != panicReason {
		t.Errorf("panic report: %+v", r)
	}
	if out := r.JSON(); !strings.Contains(out, `"block_count": 0`) || !strings.Contains(out, `"stored": null`) {
		t.Errorf("panic report JSON:\n%s", out)
	}
	if got, want := stderr.String(), "knobe-verify: internal error: boom\\x1b[2J\n"; got != want {
		t.Errorf("stderr %q, want %q", got, want)
	}
}

func TestVerifySafelyPassesReportsThrough(t *testing.T) {
	want := knobe.Report{Status: knobe.Failed, Conformance: knobe.Valid, BlockCount: 1}
	if r := verifySafely(func(string) knobe.Report { return want }, "x", io.Discard); r.Status != want.Status || r.BlockCount != 1 {
		t.Errorf("got %+v", r)
	}
}
