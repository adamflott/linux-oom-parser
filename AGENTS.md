# Repository guidance

These instructions apply to the entire repository.

## Project

`linux-oom-parser` is a Rust library and four CLI tools for parsing, analyzing,
comparing, formatting, and splitting Linux OOM killer logs. It uses `winnow`
parsers and runs without Linux-only APIs, live system inspection, or external
commands. Keep support for Rust 1.85 and edition 2024, as declared in `Cargo.toml`.

## Where to work

- `src/lib.rs`: public exports, core message types, parsing entry points, and
  lossless record output.
- `src/diagnostics.rs` and `src/types.rs`: diagnostic parsers and typed data.
- `src/events.rs`: OOM capture boundaries, task layouts, and reaper association.
- `src/timestamps.rs`: uptime and wall-clock timestamp parsing.
- `src/gfp.rs`: version-specific numeric GFP mask decoding.
- `src/analysis.rs`: findings, evidence, and page-size inference.
- `src/report.rs`, `src/comparison.rs`, and `src/format.rs`: analysis reports,
  before/after comparisons, and readable log formatting.
- `src/bin/`: `oom-analyze`, `oom-compare`, `oom-format`, and `oom-split`.
- `tests/`: integration tests organized by behavior, with CLI tests in `cli.rs`
  and byte-for-byte preservation tests in `roundtrip.rs`.
- `examples/` and `tests/fixtures/`: sample programs and captured kernel logs.

## Implementation conventions

- Follow the existing module structure and rustfmt style. Use `winnow` for
  supported message grammars and require complete message consumption.
- Unsafe code is forbidden. Clippy denies `unwrap` and `expect`; tests use
  explicit allowances where appropriate. Handle errors in library
  and CLI code rather than adding broad lint allowances.
- Document public APIs and maintain existing `#[non_exhaustive]` conventions.
  Update `README.md` and API examples when user-visible behavior changes.
- Add focused regression coverage for behavior changes in the relevant test
  file. Prefer existing fixtures and small synthetic logs that demonstrate the
  behavior and its boundary cases.
- Keep captured fixtures intact. Preserve the upstream license and provenance
  in `tests/fixtures/oomanalyser/` when using or adding third-party captures.

## Behavior to preserve

- `Record` and `OomEvent` display their original source snapshots. Preserve
  prefixes, whitespace, decimal precision, line endings, and missing final
  newlines. Editing typed fields does not rewrite those snapshots.
- Whole-log parsing captures OOM regions conservatively; `parse_line` parses
  standalone diagnostics without event context. Keep unrelated diagnostics out
  of events, retain incomplete events, and report malformed supported records
  with original source line numbers.
- Keep bytes, pages, and event counters distinct. Kernel kB/KB means 1024 bytes;
  use checked conversions. Missing measurements remain unknown, not zero.
- Derive page size from the source log or an explicit override, never the host.
  Analysis and formatting fall back to 4096 bytes when inference is unavailable.
  Task table headers determine layouts rather than kernel version strings.
- Keep uptime and wall-clock timestamps independent. Do not infer missing years,
  timezones, or timestamps from adjacent records.
- Tie analysis to captured evidence and source lines. Retain uncertainty and
  conflicting measurements; snapshots do not prove leaks or causality.
- CLI tools parse complete inputs before producing reports or files. Preserve
  stdin handling, error exit statuses, and `oom-split`'s refusal to overwrite an
  existing output directory.

## Validation

For Rust changes, run the documented checks from the repository root:

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

For public API documentation changes, also run `cargo doc --no-deps`.
For packaging changes, inspect `cargo package --list`.
Documentation-only edits do not require the Rust test suite; verify referenced
paths and commands instead. Report checks that could not be completed.

A representative CLI invocation is:

```sh
cargo run --bin oom-analyze -- tests/fixtures/oomanalyser/archlinux_6_1_1.log
```
