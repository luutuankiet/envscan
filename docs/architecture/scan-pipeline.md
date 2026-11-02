---
title: The scan pipeline
covers: where envscan scan finds the .env, decides which files to read, matches, extracts candidates, prints the report and picks the exit code
verified: 2026-11-01
---

# The scan pipeline

`envscan scan` loads rules from a `.env`, walks the paths it was given, matches
known values, extracts broad candidates, and prints one report. Every subcommand
reuses the first two steps, so this is the area to read before touching any of
them.

Line numbers below are a **starting point, not an address**. Jump roughly there,
confirm by what the code says, and if a range is off by more than a screen, fix
it here and re-date the page.

## Where each step lives

| step | file and lines | what lives there |
|---|---|---|
| entry and order of work | `src/scan.rs` 32-118 | `run`: load rules, refuse a missing path before any work, read stdin, walk, scan files in parallel, judge, finish |
| finding the `.env` | `src/env.rs` 13-66 | `discover` and `example_for`: an explicit `--env`, else `.env` at the repo root; `.env.example` beside it. One definition shared by every subcommand and the gate |
| parsing the `.env` | `src/env.rs` 111-200 | `EnvFile::parse`, `rules`, `short_keys`, `empty_keys`; read line by line, never sourced |
| what is in scope | `src/walker.rs` 17-128 | `GENERATED_DIRS`, `is_secret_name`, `walk` |
| text files | `src/scan.rs` 473-518 | `scan_file` and `scan_bytes`: files over 2,000,000 bytes, binary (a NUL in the first 8 KB) and non-UTF-8 files are skipped and counted |
| data files | `src/extract.rs` 39-56, `src/data.rs` | `csv tsv jsonl ndjson` are streamed through known-value matching with no size cap and no extractor; `xlsx parquet sqlite` and the other binary forms are only listed |
| broad candidates | `src/extract.rs` 9-150 | 13 ordered shapes per line, lines over 4096 bytes skipped; a port of a Python reference held to it by `tests/extract.rs` and `tests/fixtures/broad/` |
| the report | `src/report.rs` | field order and key names are a contract for `--json` readers |
| the exit code | `src/exit.rs` 21-31, `src/scan.rs` 300-388 | `Exit::decide` and `finish` |

## Scope rules worth knowing before you change the walker

- Scope is **the walk root's own ignore rules and below**. Naming `tmp/topic` as
  the root scans it even when the repo ignores `tmp/`; scanning the repo root
  prunes that same `tmp/`. `--no-ignore` turns ignore rules and generated-dir
  pruning off.
- `.git`, `.env` and secret-named files (`*.pem`, `*.key`, `id_rsa*`,
  `credentials.json` and so on) stay excluded even under `--no-ignore`.
  `.env.example`, `.env.sample` and `.env.template` stay **in** scope, because a
  value in a committed example is a real leak.
- Accepted gap, commented at `src/walker.rs` 7-9: an outer ignore rule also
  applies inside a nested repo below the root.

## The exit contract

| exit | meaning |
|---|---|
| 0 | scanned, no known value found |
| 1 | a known value was found, strict or loose |
| 2 | no rules loaded; candidates are still printed |
| 3 | usage or IO error, missing path, nothing scanned, or a data file left unscanned |

A leak outranks everything; an incomplete scan outranks "no rules"; neither may
read as clean. **Broad candidates never change the exit code.** They are a list
for a person or a judge to look at, not a verdict.

## General rule

Anything that could make a partial scan look complete (a skipped file, an
unreadable path, a report that failed to print) must end in a non-zero exit with
a line on stderr saying "this is not a clean result". Keep that property when
adding a new input kind.
