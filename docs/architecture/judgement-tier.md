---
title: The judgement tier
covers: how envscan scan decides between plain and live judgement, where the tier and the vendor key are read from, which lines may be sent to the vendor model, and what happens when judging fails
verified: 2026-11-01
---

# The judgement tier

Broad candidates (an IP, a hostname, an email shape) are noisy. With the tier set
to `live`, `envscan scan` sends some flagged lines to a vendor model that scores
how likely each candidate is a private identifier, and drops the ones under the
threshold. Everything else about the scan (known-value matching, the exit code)
is the same in both tiers. **Candidates never change the exit code**, judged or
not.

Line numbers below are a **starting point, not an address**. Jump roughly there,
confirm by what the code says, and if a range is off by more than a screen, fix
it here and re-date the page.

## Where each step lives

| step | file and lines | what lives there |
|---|---|---|
| the saved tier | `src/config.rs` 21-41 | `saved_tier`: reads `~/.config/envscan/config.toml`; `auto` or no file is unset; anything unreadable is `Bad` and runs plain |
| the vendor key | `src/config.rs` 43-72 | `api_key`: the `TYPESAFE_API_KEY` environment variable, then `~/.config/envscan/env` |
| saving the tier | `src/config.rs` 74-101 | `envscan config tier auto\|live\|plain`, written by rename so a reader never sees half a file |
| choosing the tier | `src/scan.rs` 111-138 | `Tier::choose`, decided before any file is read so a bad setup sends nothing |
| which files may be sent | `src/scan.rs` 74-93 | the `named` set and the `sendable` flag per file |
| which lines may be sent | `src/scan.rs` 340-356 | `extract_text`: a line that already holds a known value is withheld |
| running it, and falling back | `src/scan.rs` 140-163 | `Tier::run` and `Ran::fallback` |
| sending and tallying | `src/scan.rs` 165-226 | `judge_pending`: one request per distinct line, the cost estimate, the candidate cap, the threshold |
| the vendor call | `src/judge.rs` 10-23, 55-60, 113-196 | constants, `eligible_name`, `Client`, `judge` |

## Where the tier and the key come from

- The tier is machine-wide, in `~/.config/envscan/config.toml`. Unset or `auto`
  runs plain with one reminder line on stderr. `--known-only` forces plain.
- The key comes from the process environment, then from `~/.config/envscan/env`,
  which is parsed and never sourced. That file is refused if it is readable by
  group or other.
- **A repo `.env` is never read for the key.** Every value in a repo `.env` is
  text the scanner blocks, so a key there would be a contradiction.
- `live` with no usable key does not fail the scan: the report says
  `plain (fallback from live: <reason>)`, and the reason never holds any part of
  the key.

## What may leave the machine

All three must hold for a line to be sent:

1. **The file was named on the command line.** `envscan scan notes.md` may send
   lines from `notes.md`; `envscan scan docs/` sends nothing from the files it
   walks under `docs/`. Stdin is never sent. The caller names what it is willing
   to share; a walk can reach anything.
2. **The extension is one of `md txt py sh sql yml yaml toml`** (`src/judge.rs`
   line 23, checked by `eligible_name`). A `.log` or `.json` file gets
   known-value matching only. Widening this is tracked in issue #11, "Judge .log
   and .json files". The report counts files that were scanned but not judged in
   `files_known_only`, so the gap is visible, not silent.
3. **The line holds no known value.** A line with a known-value hit is withheld
   and counted in `lines_withheld`; it is already a leak, and sending it would
   send the value.

Each request carries the line, its relative path and the candidate values, and
nothing else. Identical lines are sent once.

## Failure is all or nothing

- Any failed request, a malformed answer, or a probability outside 0 to 1 fails
  the whole run, and the plain candidates stand untouched. One report never mixes
  judged and unjudged candidates.
- More candidates than `--max-candidates` (default 5000) is a failure before
  anything is sent. The estimated cost is printed to stderr first.
- A candidate is kept when its probability is above 0.3 (`THRESHOLD`).
- `ENVSCAN_JEV_ENDPOINT` points the binary at a test stub, and is refused unless
  it is a loopback URL, so it cannot carry a line or the key elsewhere. The
  replay-only switch that widens eligibility to every extension is honoured only
  beside that loopback override.

## General rule

Any new input to the judge must answer "who chose to send this?" before "is it
useful to send?". A path the caller named is consent; a path the walker found is
not. Keep that split when adding a new file kind or input source.
