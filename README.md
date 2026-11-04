# knobe-go

A KNOBE verifier for Go: an independent verifier for **KNOBE Protocol v1** `.knobe.md` files, written as a sibling of the reference verifier `lens.py` in [KnobeOne/knobe-protocol](https://github.com/KnobeOne/knobe-protocol).

The current release is v0.1.0, with API documentation on [pkg.go.dev](https://pkg.go.dev/github.com/KnobeDev/knobe-go).

> A match proves integrity, not truth. A `valid` proves conformance, not truth. Inspect before trusting.

## What it does and does not do

knobe-go reads a `.knobe.md` file and reports three independent results from spec §7. **status** (integrity) is `verified`, `verified-body-modified`, `failed` or `unreadable`. **body_verified** (the optional body hash) is `yes`, `modified` or `omitted`. **conformance** (schema compliance) is `valid`, `warnings` or `invalid`. To get these it applies the §5 canonical hash rule and the §6 body normalization, and it rejects as `unreadable` any payload with duplicate keys, keys that collide under NFC, a non-object payload, or an unsupported `spec_version`. Its reports and exit codes match `lens.py` field for field, and every payload-derived string is escaped before it is printed. It does **not** seal, create or transform KNOBE files. It does not check that content is accurate, that attribution is honest, or that a file is fit for any use: a `verified` result only proves the payload is byte-identical to what was sealed. It runs entirely locally and never makes a network request.

## Install and use

Requires Go 1.22 or later.

```bash
go install github.com/KnobeDev/knobe-go/cmd/knobe-verify@latest
```

To install exactly this release rather than the newest one, use `@v0.1.0` in place of `@latest`.

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
go get github.com/KnobeDev/knobe-go@v0.1.0
```

```go
import knobe "github.com/KnobeDev/knobe-go"

r := knobe.VerifyFile("file.knobe.md") // or knobe.VerifyBytes(data)
fmt.Println(r.Status, r.BodyVerified, r.Conformance, r.ConformanceIssues)
```

The full API is on [pkg.go.dev](https://pkg.go.dev/github.com/KnobeDev/knobe-go).

## Test vector results

These are the results against the published vectors at knobe-protocol commit `c7ada1f`. Every one matches the expected result in that directory's README. The first nine are the conformance bar.

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
| `parity_test.go` | Runs `lens.py --json` side by side with this verifier over every published `.knobe.md` (75 files) and 123 crafted hostile files. It compares state, conformance, body_verified, computed and stored hash, block count and exit code, the fields upstream's `knobe-core.selftest.mjs` compares. The hostile files are sealed by an independent Python oracle (`testdata/pyhash.py`), never by the code under test. |
| `unit_test.go` | The JSON parser, Python-compatible float repr and string helpers, Base64 rules, canonical form, body normalization, block and frontmatter parsing, and output escaping |

On top of the tests, the human-readable output and the complete `--json` output are byte-identical to `lens.py` on all 75 published files.

CI runs against upstream `main`, so an upstream change that breaks parity shows up immediately.

## Behavior beyond lens.py

knobe-go reports `unreadable` (exit 2) in a few cases where `lens.py` itself crashes with a Python traceback. It never crashes on any input.

| Input | lens.py | knobe-go |
|---|---|---|
| A float that overflows to infinity, such as `1e400` | Traceback from `json.dumps` | `unreadable` |
| Nesting deeper than 996 levels | Traceback (`RecursionError`) | `unreadable` |
| A non-string, non-hashable `spec_version`, such as a list | Traceback (`TypeError`) | `unreadable` (unsupported spec_version) |

`knobe-verify` reads at most 64 MiB (`knobe.MaxFileSize`) and reports a larger file as `unreadable`. Parsing takes about 30 bytes of memory per input byte, and `lens.py` has no limit. Library callers of `VerifyBytes` should bound their input the same way.

The human report escapes more than `lens.py` does. It also escapes control characters in `stored_hash` and in conformance issue text, which `lens.py` prints raw, so a crafted key or hash cannot carry terminal escape sequences through them. It also escapes Unicode format characters, such as bidi overrides and isolates (U+202E, U+2066), zero-width characters and U+FEFF, as `\uNNNN`, so a crafted title cannot reorder or hide text in the report. The `--json` output is unchanged and matches `lens.py`.

## Provenance

knobe-go is maintained by Joshua Hori (KnobeDev). It is not an official or reference KNOBE implementation, and the KNOBE steward did not build, review or endorse it.

It was written with AI assistance (Claude) at the maintainer's direction. As the steward's [governance notes](https://github.com/KnobeOne/knobe-protocol/blob/main/GOVERNANCE.md) ask, the reliance on the reference engines is disclosed here: `lens.py` was consulted throughout, along with the maintainer's Rust port, [knobe-rs](https://github.com/KnobeDev/knobe-rs) (on crates.io as [`knobe`](https://crates.io/crates/knobe)), which follows the same reference. Every ambiguous case was settled by observing `lens.py` and is pinned by the parity tests above.

## License

Apache-2.0, matching the upstream verifier code. This is an independent implementation: it shares no code with upstream but follows the behavior of `lens.py`. See [NOTICE](NOTICE).
