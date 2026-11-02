---
title: The judgement tier
covers: how envscan scan decides between plain and live judgement, where the tier and the vendor key are read from, which lines may be sent to the vendor model, and what happens when judging fails
verified: 2026-11-02
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
| the saved tier | `src/config.rs` 26-41 | `saved_tier`: reads `~/.config/envscan/config.toml`; `auto` or no file is unset; anything unreadable is `Bad` and runs plain |
| the vendor key | `src/config.rs` 43-72 | `api_key`: the `TYPESAFE_API_KEY` environment variable, then `~/.config/envscan/env` |
| saving the tier | `src/config.rs` 74-101 | `envscan config tier auto\|live\|plain`, written by rename so a reader never sees half a file |
| choosing the tier | `src/scan.rs` 120-147 | `Tier::choose`, decided before any file is read so a bad setup sends nothing |
| which files may be sent | `src/scan.rs` 85-103 | the `named` set and the `sendable` flag per file |
| which lines may be sent | `src/scan.rs` 412-432 | `extract_text`: a line that already holds a known value is withheld |
| running it, and falling back | `src/scan.rs` 149-172 | `Tier::run` and `Ran::fallback` |
| sending and tallying | `src/scan.rs` 174-266 | `judge_pending`: one request per distinct line, the cost estimate, the candidate cap, the threshold |
| the vendor call | `src/judge.rs` 12-31, 53-59, 135-277 | constants, `eligible_name`, `Client`, `judge` |

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
2. **The extension is one of `md txt py sh sql yml yaml toml log json diff`**
   (`EXTENSIONS` in `src/judge.rs`, checked by `eligible_name`). `Dockerfile`,
   `.env.example` and other files outside the list get known-value matching only.
   The report counts files that were scanned but not judged in
   `files_known_only`, so the gap is visible, not silent.
3. **The line holds no known value.** A line with a known-value hit is withheld
   and counted in `lines_withheld`; it is already a leak, and sending it would
   send the value.

Each request carries the line, its relative path and the candidate values, and
nothing else. Identical lines are sent once.

## Failure is all or nothing, except a line over the vendor's limit

- A failed request, a malformed answer, or a probability outside 0 to 1 fails the
  whole run, and the plain candidates stand untouched. The report then has no
  `judgement`, `rejected` or `unjudged`.
- The one exception is a 400 with `error_type` `max_tokens_exceeded`. It is not
  retried, and marks only that line unjudged with `over-limit-line`. The run
  continues. Any other 400 fails the run.
- To stay under that limit, one line's values split across requests sized by
  `values_per_request` from the line's length and a budget of 33,000 tokens (see
  `REQUEST_TOKEN_BUDGET`). Verdicts merge back in value order. `lines_sent` still
  counts distinct lines, so requests can outnumber it. `candidates_sent` includes
  the values of a refused line, so `kept` plus `rejected` can be lower than it.
- More candidates than `--max-candidates` (the whole-run limit, default 25,000)
  is a failure before anything is sent. The worst-case cost, modelled per value
  plus per line, is printed to stderr first.
- A file with more candidates than `--max-file-candidates` (default 5,000) sends
  nothing, and its candidates are listed unjudged with `over-cap-file`. The rest
  of the run proceeds. A line it shares with an uncapped file is still judged for
  that file. Withheld lines do not count towards the cap.
- A candidate is kept when its probability is above 0.3 (`THRESHOLD`).
- `ENVSCAN_JEV_ENDPOINT` points the binary at a test stub, and is refused unless
  it is a loopback URL, so it cannot carry a line or the key elsewhere.

## What a live report lists besides the survivors

`candidates` holds only survivors and withheld lines. Two more lists appear when
the live tier ran, and are absent on a plain or fallback run:

- `unjudged`: `kind`, masked value (full value only with `--full`), location, and
  a `reason` of `known-only-file`, `over-limit-line` or `over-cap-file`.
- `rejected`: values of shape `ip`, `email`, `home-path`, `account-id`, `bucket`
  or `gh-repo` scored at or under the threshold, with `p` and `judged_kind`. Other
  shapes still drop. `judgement.rejected` counts every rejected verdict, and
  `judgement.rejected_listed` counts the occurrences kept in this list.

Neither list is cut by `--top`. The text form caps each at 20 unless `--full`.

## General rule

Any new input to the judge must answer "who chose to send this?" before "is it
useful to send?". A path the caller named is consent; a path the walker found is
not. Keep that split when adding a new file kind or input source.
