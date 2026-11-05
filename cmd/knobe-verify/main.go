// Command knobe-verify checks a KNOBE Protocol v1 file and reports its
// integrity (status), body hash result (body_verified) and spec conformance,
// with the same report and exit codes as the reference verifier lens.py.
package main

import (
	"fmt"
	"os"

	knobe "github.com/KnobeDev/knobe-go"
)

const usage = `usage: knobe-verify [--json] FILE.knobe.md
       knobe-verify --help`

const help = usage + `

Reports three independent dimensions of a KNOBE Protocol v1 file:

  status         verified | verified-body-modified | failed | unreadable
  body_verified  yes | modified | omitted
  conformance    valid | warnings | invalid

--json prints the report in the same JSON shape as python3 lens.py --json.

Exit codes:
  0  verified or verified-body-modified, and conformance valid or warnings
  1  verified/verified-body-modified but conformance invalid, OR status failed
  2  unreadable, or a usage/file error

Verification is local: this tool never makes a network request.
A match proves integrity, not truth. A valid result proves conformance, not
truth. Inspect before trusting.`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Println(help)
		return 0
	}
	asJSON := false
	if len(args) > 0 && args[0] == "--json" {
		asJSON, args = true, args[1:]
	}
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	r := verifySafely(knobe.VerifyFile, args[0])
	if asJSON {
		fmt.Println(r.JSON())
	} else {
		r.WriteHuman(os.Stdout)
	}
	return r.ExitCode()
}

const panicReason = "verifier error (panic); rejected"

// verifySafely is the command-line guard lens.py has: hostile input must
// never end in a stack trace. A panic (which would be a bug in knobe-go) is
// reported the way lens.py reports an exception from verify(): unreadable,
// with no blocks and no payload. The panic value goes to stderr, escaped,
// for a bug report.
func verifySafely(verify func(string) knobe.Report, path string) (r knobe.Report) {
	defer func() {
		if v := recover(); v != nil {
			fmt.Fprintln(os.Stderr, "knobe-verify: internal error:", knobe.SafeString(fmt.Sprint(v), 300))
			r = knobe.Report{
				Status:            knobe.Unreadable,
				Conformance:       knobe.Invalid,
				ConformanceIssues: []string{panicReason},
				Reason:            panicReason,
			}
		}
	}()
	return verify(path)
}
