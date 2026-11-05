package main

import (
	"strings"
	"testing"

	knobe "github.com/KnobeDev/knobe-go"
)

func TestVerifySafelyReportsPanicAsUnreadable(t *testing.T) {
	r := verifySafely(func(string) knobe.Report { panic("boom") }, "x.knobe.md")
	if r.Status != knobe.Unreadable || r.Conformance != knobe.Invalid || r.ExitCode() != 2 || r.Reason != panicReason {
		t.Errorf("panic report: %+v", r)
	}
	if out := r.JSON(); !strings.Contains(out, `"block_count": 0`) || !strings.Contains(out, `"stored": null`) {
		t.Errorf("panic report JSON:\n%s", out)
	}
}

func TestVerifySafelyPassesReportsThrough(t *testing.T) {
	want := knobe.Report{Status: knobe.Failed, Conformance: knobe.Valid, BlockCount: 1}
	if r := verifySafely(func(string) knobe.Report { return want }, "x"); r.Status != want.Status || r.BlockCount != 1 {
		t.Errorf("got %+v", r)
	}
}
