# knobe-go

A KNOBE verifier for Go: an independent verifier for **KNOBE Protocol v1** `.knobe.md` files, written as a sibling of the reference verifier `lens.py` in [KnobeOne/knobe-protocol](https://github.com/KnobeOne/knobe-protocol).

The current release is v0.1.2, with API documentation on [pkg.go.dev](https://pkg.go.dev/github.com/KnobeDev/knobe-go). It follows `lens.py` as of knobe-protocol commit `6132595`, which includes ERRATA E12 and upstream's hostile-input hardening. How it prints hostile text follows a patch series proposed to KnobeOne/knobe-protocol and not yet merged (see [Changes in v0.1.2](#changes-in-v012)).

> A match proves integrity, not truth. A `valid` proves conformance, not truth. Inspect before trusting.

## What it does and does not do

knobe-go reads a `.knobe.md` file and reports three independent results from spec §7. **status** (integrity) is `verified`, `verified-body-modified`, `failed` or `unreadable`. **body_verified** (the optional body hash) is `yes`, `modified` or `omitted`. **conformance** (schema compliance) is `valid`, `warnings` or `invalid`. To get these it applies the §5 canonical hash rule and the §6 body normalization, and it rejects as `unreadable` any payload with duplicate keys, keys that collide under NFC, a number that overflows to infinity, an unpaired surrogate, a non-object payload, or an unsupported `spec_version`. Following ERRATA E12, hash and date formats are ASCII-strict (exactly 64 lowercase hex characters, exactly `YYYY-MM-DD`, nothing after either), and only ASCII space, tab, CR and LF may be stripped from a payload block. Its reports and exit codes match `lens.py` field for field, and every payload-derived string is escaped before it is printed. It does **not** seal, create or transform KNOBE files. It does not check that content is accurate, that attribution is honest, or that a file is fit for any use: a `verified` result only proves the payload is byte-identical to what was sealed. It runs entirely locally and never makes a network request.

## Install and use

Requires Go 1.22 or later.

```bash
go install github.com/KnobeDev/knobe-go/cmd/knobe-verify@latest
```

To install exactly this release rather than the newest one, use `@v0.1.2` in place of `@latest`.

```bash
knobe-verify path/to/file.knobe.md
```

```bash
knobe-verify --json path/to/file.knobe.md
```

The human report and the `--json` document have the same layout and keys as `python3 lens.py` and `python3 lens.py --json`.

| Exit code | Meaning |
|---|---|
| 0 | `verified` or `verified-body-modified`, and conformance `valid` or `warnings` |
| 1 | Integrity holds but conformance is `invalid`, or status is `failed` |
| 2 | `unreadable`, or a usage or file error |

### As a library

```bash
go get github.com/KnobeDev/knobe-go@v0.1.2
```

```go
import knobe "github.com/KnobeDev/knobe-go"

r := knobe.VerifyFile("file.knobe.md") // or knobe.VerifyBytes(data)
fmt.Println(r.Status, r.BodyVerified, r.Conformance, r.ConformanceIssues)
```

The full API is on [pkg.go.dev](https://pkg.go.dev/github.com/KnobeDev/knobe-go).

## Test vector results

These are the results against the published vectors at knobe-protocol commit `6132595`. Every one matches the expected result in that directory's README. The first nine are the conformance bar. ERRATA E12 changed no vector's result.

| file | status | body_verified | conformance | exit |
|---|---|---|---|---|
| `minimal-valid.knobe.md` | verified | omitted | valid | 0 |
| `full-valid.knobe.md` | verified | yes | valid | 0 |
| `body-modified.knobe.md` | verified-body-modified | modified | valid | 0 |
| `payload-modified.knobe.md` | failed | omitted | valid | 1 |
| `unreadable.knobe.md` | unreadable | omitted (null) | invalid | 2 |
| `unicode-valid.knobe.md` | verified | yes | valid | 0 |
| `numeric-violation.knobe.md` | verified | yes | invalid | 1 |
| `omitted-body-hash.knobe.md` | verified | omitted | valid | 0 |
| `multi-block.knobe.md` | verified | omitted | warnings | 0 |
| `adversarial/bad-attribution-sources-type.knobe.md` | verified | omitted | invalid | 1 |
| `adversarial/bad-body-hash-format.knobe.md` | verified-body-modified | modified | invalid | 1 |
| `adversarial/bad-created-date.knobe.md` | verified | omitted | invalid | 1 |
| `adversarial/control-character-title.knobe.md` | verified | omitted | valid | 0 |
| `adversarial/duplicate-key.knobe.md` | unreadable | omitted (null) | invalid | 2 |
| `adversarial/multi-block-warning.knobe.md` | verified | omitted | warnings | 0 |
| `adversarial/nfc-key-collision.knobe.md` | unreadable | omitted (null) | invalid | 2 |
| `adversarial/no-frontmatter-valid-payload.knobe.md` | verified | omitted | invalid | 1 |
| `adversarial/payload-array.knobe.md` | unreadable | omitted (null) | invalid | 2 |
| `adversarial/unsupported-spec-version.knobe.md` | unreadable | omitted (null) | invalid | 2 |
| `interpretation/astral-unicode-literal.knobe.md` | verified | omitted | valid | 0 |
| `interpretation/attribution-missing.knobe.md` | verified | omitted | invalid | 1 |
| `interpretation/base64-unpadded.knobe.md` | unreadable | omitted (null) | invalid | 2 |
| `interpretation/begin-marker-mid-line.knobe.md` | verified | yes | valid | 0 |
| `interpretation/boolean-null-values.knobe.md` | verified | omitted | valid | 0 |
| `interpretation/spec-version-frontmatter-mismatch.knobe.md` | verified | omitted | warnings | 0 |

For an unreadable file, `--json` prints `body_verified` as `null`, as `lens.py` does. ERRATA E11 accepts either `null` or `omitted`.

The control-character title prints escaped, never raw:

```
title:             ALERT\x1b[31mINJECTED\x1b[0m\x0astatus:            verified (SPOOFED)
```

## How it is tested

`go test` needs a checkout of knobe-protocol at `../knobe-protocol`. Set `KNOBE_PROTOCOL_DIR` to use a different location. The differential tests also need `python3`, and they skip themselves when it is missing.

| Test | What it checks |
|---|---|
| `vectors_test.go` | All 25 published vectors (core, adversarial, interpretation) against the expected results in their READMEs, plus exit codes and the ERRATA E5/E9 issue text |
| `parity_test.go` | Runs `lens.py` side by side with this verifier over every published `.knobe.md` (75 files) and 209 crafted hostile files. It first compares state, conformance, body_verified, computed and stored hash, block count and exit code, the fields upstream's `knobe-core.selftest.mjs` compares. It then requires the complete `--json` document, every conformance issue and unreadable reason included, and the human report with its exit code, to be byte-identical on all 284 files. The hostile files are sealed by an independent Python oracle (`testdata/pyhash.py`), never by the code under test. |
| `display_test.go` | The display rules: `SafeString`'s exact escape set and truncation, duplicate keys holding surrogates, Python `repr()` (checked against `str.isprintable()` on every code point), the UTF-8 error text, file names and `OSError` text, and the human report fields |
| `unit_test.go` | The JSON parser, Python-compatible float repr and string helpers, Base64 rules, canonical form, body normalization, block and frontmatter parsing, and the lone-surrogate and nesting walk |
| `cmd/knobe-verify/paths_unix_test.go` | File names holding `0xFF`, ESC, U+202E or a quote, for a missing file, a valid file, a directory, an unreadable file and a path through a file: `knobe-verify` must print what `lens.py` prints, `--json` and human, exit code included, and the reasons must read as specified |
| `cmd/knobe-verify/main_test.go` | The command-line guard that reports an internal error as `unreadable` |

CI runs against upstream `main` on Python 3.13, so an upstream change that breaks parity shows up immediately. The nesting limits below are CPython 3.13's. On another Python version, the twelve cases that depend on its `json.loads` limits are skipped, with a note in the test log.

Upstream `main` does not have the display patch series yet (see [Changes in v0.1.2](#changes-in-v012)). The tests check once whether the `lens.py` under test has it. If it does, every file and path must match byte for byte. If it does not, a listed set of cases, each with its reason, must differ (an unpatched `lens.py` crashes on some of them), and every other case must match. The test log says which mode ran. Once upstream merges the series, the listed cases must match like the rest.

## Hostile input

Since upstream PR #11, `lens.py` reports hostile input as `unreadable` instead of crashing, and knobe-go reports exactly what it reports, reason text included:

| Input | Reported as |
|---|---|
| A float that overflows to infinity, such as `1e400`, anywhere in the payload, `payload_hash` included | `unreadable`: non-JSON numeric constant |
| A non-string `spec_version`, such as a list | `unreadable`: unsupported spec_version, shown as Python `str()` shows it |
| A value or key nested 499 or more levels below the payload | `unreadable`: `verifier error (RecursionError); rejected`, with a block count of 0 |
| An object, a float, or `NaN`/`Infinity` nested more than 9995 levels below the payload | `unreadable`: payload could not be decoded or parsed |
| An array nested more than 9997 levels below the payload | `unreadable`: payload could not be decoded or parsed |

The last three limits come from CPython 3.13. `lens.py`'s lone-surrogate check spends two stack frames per level against Python's 1000-frame limit, and `json.loads` stops at its C recursion limit, two levels earlier for a node that calls one of `lens.py`'s Python hooks (objects, floats and the non-JSON constants). Integers, strings, `true`, `false` and `null` call no hook and may sit as deep as their array.

Hostile text is printed escaped, never raw, in reasons, conformance issues and the human report. C0 and C1 control characters and DEL show as `\xNN`. Bidi embeddings, overrides and isolates (U+202A to U+202E, U+2066 to U+2069), the line and paragraph separators (U+2028, U+2029) and unpaired surrogates show as `\uNNNN`. Everything else, including zero-width characters and U+FEFF, prints as it is. A duplicate key or `spec_version` in a reason is cut at 300 characters, and so are the human report's `unreadable` status line and its `title` (a string; any other title is shown whole), `spec_version`, `quarantine_status`, `privacy_level` and `stored_hash` lines. File names and conformance issues are never cut. A file name shows as Python holds it, so a byte that is not UTF-8 shows as `\udcXX`. A file that cannot be read is reported with Python's error text, such as `could not read file: [Errno 13] Permission denied: '/tmp/x\udcff.knobe.md'`.

knobe-go never crashes on any input. As a last line of defense, as in `lens.py`, `knobe-verify` would report an internal error as `unreadable` (`verifier error (panic); rejected`) rather than print a stack trace.

## Behavior beyond lens.py

`knobe-verify` reads at most 64 MiB (`knobe.MaxFileSize`) and reports a larger file as `unreadable`. An ordinary file takes about 25 bytes of memory per input byte to verify. A crafted file of many deeply nested arrays takes far more: about 9 GB at the 64 MiB limit, in v0.1.0 as in v0.1.1. `lens.py` takes about 5 GB on the same file and has no size limit. Library callers of `VerifyBytes` should bound their input to what their host can spare.

Until upstream merges the display patch series, knobe-go's output differs from `lens.py` on `main` where hostile text is shown: a duplicate key, `spec_version`, title or `privacy_level` holding a bidi control or U+2028/U+2029, a `stored_hash` or conformance issue holding a control character, a long `stored_hash`, and the name of a missing file or a directory. Where `lens.py` on `main` crashes printing a report (a duplicate key holding an unpaired surrogate, or a file name that is not UTF-8), knobe-go prints the report. Otherwise verdicts and exit codes are the same.

## Changes in v0.1.2

v0.1.2 follows a common display contract for KNOBE verifiers. It is the one in the patch series proposed to KnobeOne/knobe-protocol ("Never crash printing a report; escape the same characters in lens.py and knobe-core.js"), which is not yet merged. knobe-rs follows it too. No verdict or exit code changes.

- **Escaping.** Hostile text is escaped by an exact set of characters (see [Hostile input](#hostile-input)). v0.1.1 escaped every Unicode format character, zero-width characters and U+FEFF included, and showed an unpaired surrogate in a duplicate key as U+FFFD.
- **Human report.** `stored_hash`, and a non-string `spec_version`, `quarantine_status` or `privacy_level`, are shown as Python `str()` shows the value, escaped and cut at 300 characters. v0.1.1 printed them whole.
- **File names.** A missing file, a directory or an oversized file is named as Python holds the name, escaped, with `\udcXX` for a byte that is not UTF-8. v0.1.1 printed the raw bytes, and its `--json` output could be invalid UTF-8. Other read errors are reported with Python's `OSError` text.
- **Invalid UTF-8.** A file that is not valid UTF-8 is reported with Python's codec detail, as `lens.py` reports it, such as `file is not valid UTF-8: 'utf-8' codec can't decode byte 0xc3 in position 39: invalid continuation byte`.
- **Nesting.** An object, a float, or `NaN`/`Infinity` nested more than 9995 levels deep makes the payload unparseable, as in CPython 3.13. v0.1.1 applied the array limit (9997) to objects too, so it reported, for example, a duplicate key that `lens.py` cannot parse.
- **Tests.** The human report is now compared with `lens.py` on every hostile file too, and file names are compared in a new test. 53 new hostile cases (209 total). The full `--json` comparison has no exceptions left.

## Changes in v0.1.1

v0.1.0 predates two upstream changes merged on 2026-11-04, and its tests fail against upstream `main`. v0.1.1 matches them.

- **ERRATA E12, hash format.** A `payload_hash`, `body_hash` or `parents[i].payload_hash` followed by a newline is now `invalid`. v0.1.0 accepted the newline, as Python's `$` did.
- **ERRATA E12, block whitespace.** Only ASCII space, tab, CR and LF are stripped from a payload block. Any other whitespace, such as NEL (U+0085), NBSP, VT, FF or U+001C to U+001F, makes the file `unreadable`. v0.1.0 stripped everything Python's `str.split()` does.
- **ERRATA E12, date format.** `created_date` must be ASCII digits with nothing after. Such dates were already `invalid`; the issue now reads "not in YYYY-MM-DD form", as `lens.py`'s does.
- **Overflowing numbers.** A float such as `1e400` makes the file `unreadable` wherever it appears. In `payload_hash`, v0.1.0 reported `failed` and printed a bare `Infinity` in `--json`, which is not valid JSON.
- **Check order and nesting.** The lone-surrogate check now runs before the NFC and `spec_version` checks. A duplicate key is reported only if the rest of its object parses, as Python does. Nesting limits follow `lens.py` (see [Hostile input](#hostile-input)).
- **Command-line guard.** `knobe-verify` reports an internal error as `unreadable` instead of crashing, as `lens.py` now does.
- **Tests.** The complete `--json` output is now compared with `lens.py` on every published and hostile file, and the human report on every published file.

## Provenance

knobe-go is maintained by Joshua Hori (KnobeDev). It is not an official or reference KNOBE implementation, and the KNOBE steward did not build, review or endorse it.

It was written with AI assistance (Claude) at the maintainer's direction. As the steward's [governance notes](https://github.com/KnobeOne/knobe-protocol/blob/main/GOVERNANCE.md) ask, the reliance on the reference engines is disclosed here: `lens.py` was consulted throughout, along with the maintainer's Rust port, [knobe-rs](https://github.com/KnobeDev/knobe-rs) (on crates.io as [`knobe`](https://crates.io/crates/knobe)), which follows the same reference. Every ambiguous case was settled by observing `lens.py` and is pinned by the parity tests above.

## License

Apache-2.0, matching the upstream verifier code. This is an independent implementation: it shares no code with upstream but follows the behavior of `lens.py`. See [NOTICE](NOTICE).
