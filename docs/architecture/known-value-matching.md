---
title: Known-value matching, hydrate and dehydrate
covers: how a value from .env is matched in text, which neighbours count as a word boundary, strict versus loose hits, and how hydrate and dehydrate move text between $KEY and real values
verified: 2026-11-01
---

# Known-value matching, hydrate and dehydrate

Every subcommand that looks for a known value (`scan`, `gate`, `dehydrate`, and the
redaction of paths in error messages) goes through one matcher. `hydrate` and
`dehydrate` are the two directions of the same move: `$KEY` to value, value to
`$KEY`. Change the matcher and all of them change together.

Line numbers below are a **starting point, not an address**. Jump roughly there,
confirm by what the code says, and if a range is off by more than a screen, fix
it here and re-date the page.

## Where each step lives

| step | file and lines | what lives there |
|---|---|---|
| the boundary rule, in prose | `src/matcher.rs` 1-10 | the module comment is the specification; read it before the code |
| what counts as glued | `src/matcher.rs` 38-47 | `glued` (an ASCII letter or digit) decides matching; `word` (letter, digit or `_`) only decides whether `dehydrate` must brace a key |
| strict or loose | `src/matcher.rs` 49-61 | `classify`: `None` inside a longer word, else strict or loose |
| building the matcher | `src/matcher.rs` 63-88 | ASCII values go to one case-insensitive Aho-Corasick automaton; a non-ASCII value gets its own case-folding regex |
| finding hits | `src/matcher.rs` 100-122 | `find`: every bounded occurrence, overlapping, ordered by position |
| redacting a path | `src/matcher.rs` 124-146 | `redact`: replaces a hit with its key, so an error message never prints a value |
| which values become rules | `src/env.rs` 138-170 | `rules` and `short_keys`: a value under 3 characters is not a rule |
| hydrate | `src/hydrate.rs` 30-60, 109-153 | `fill` and `run_hydrate` |
| dehydrate | `src/hydrate.rs` 62-107, 155-184 | `replace_values` and `run_dehydrate` |

## The boundary tiers

Matching is case-insensitive. Each occurrence of a value lands in one of three
places:

| occurrence | result | example shape |
|---|---|---|
| glued to an ASCII letter or digit on a side where the value's own edge is a letter or digit | **no match**: it is inside a longer word | `xvalue`, `value2` |
| a `_` or `-` on either side, or a `.` before it | **loose** hit | `value_orders`, `stg_value`, `sub.value`, `value-raw` |
| anything else, including a non-ASCII neighbour | **strict** hit | `value`, `/value/`, `"value"` |

Both strict and loose hits are leaks: the scan exit is 1 either way. The split
exists so a report can say how confident it is. `_` is a loose boundary on
purpose, because snake_case names (tables, columns, files) are where a value most
often sits. A non-ASCII neighbour counts as a boundary so text written without
spaces between words cannot hide a value. The tests in `src/matcher.rs` below
line 149 pin each case.

## hydrate: `$KEY` to value

- The keys it will fill are the union of the keys in `.env` and in `.env.example`.
  Any other `$NAME` passes through untouched, so `$HOME` in a script survives.
- **One pass.** A value that itself contains `$OTHER` is not filled again.
- A name is read whole, as a shell reads it: `$KEY_B` is never `$KEY` followed by
  `_B`. `${KEY}` is accepted too.
- A listed key with no value is an error (exit 2, keys named on stderr), never an
  empty substitution. `--check` prints which keys are used and whether all
  resolve, and prints no value.
- It prints to stdout and never writes in place.

## dehydrate: value to `$KEY`

- **Longest value first** across the whole text, so a short value never splits a
  longer one that overlaps it, whichever starts first.
- It uses the scanner's own `find`, so dehydrated text passes the scan that gates it.
- A value that sits inside an existing `$NAME` or `${NAME}` is left alone;
  otherwise a value `home` would turn `$HOME` into `$$KEY`.
- The key is written as `${KEY}` when the next character would continue a shell
  name, else `$KEY`.
- With no rules loaded it refuses (exit 2) instead of passing the text through,
  because unchanged text would look safe to post. Values under 3 characters are
  named on stderr as not replaced; check them by hand.

## General rule

The matcher is the single definition of "this text contains a known value". If a
new caller needs a different notion of a boundary, change `classify` and its tests
so every caller moves together; a second matcher would let `dehydrate` produce
text that `scan` or the gate still rejects, or the reverse.
