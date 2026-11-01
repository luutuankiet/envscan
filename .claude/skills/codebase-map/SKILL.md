---
name: codebase-map
description: Where behaviour lives in this repo — a per-area map of which files and line ranges own what, so you can open the right file instead of searching for it. Use before hunting for where something is implemented, before adding a feature that touches existing behaviour, and when a change seems to need edits in more places than expected.
---

# Where things live

This repo is large enough that finding the right file costs more than reading it.
The pages below are maps: for each area, which files own it and roughly where in
them.

**Pick the area, open that one page, then go straight to the file.** Do not read
every page — that defeats the point.

<!-- BEGIN GENERATED INDEX -- edit the pages, not this block -->

## Where things live

One page per area of the system. Read before going looking for where
something is implemented.

| page | covers | verified |
|---|---|---|
| [The judgement tier](../../../docs/architecture/judgement-tier.md) | how envscan scan decides between plain and live judgement, where the tier and the vendor key are read from, which lines may be sent to the vendor model, and what happens when judging fails | 2026-11-01 |
| [Known-value matching, hydrate and dehydrate](../../../docs/architecture/known-value-matching.md) | how a value from .env is matched in text, which neighbours count as a word boundary, strict versus loose hits, and how hydrate and dehydrate move text between $KEY and real values | 2026-11-01 |
| [The outbound gate](../../../docs/architecture/outbound-gate.md) | what envscan gate checks before a git push leaves the machine, when a repo counts as opted in, why it denies with no leak found, and how gate install writes the pre-push hook | 2026-11-01 |
| [The promotion record](../../../docs/architecture/promotion-record.md) | envscan promotion add and status, where the record of handled tmp/ files is stored, what each handling and its ref mean, and how status decides a folder is safe to clear | 2026-11-01 |
| [The scan pipeline](../../../docs/architecture/scan-pipeline.md) | where envscan scan finds the .env, decides which files to read, matches, extracts candidates, prints the report and picks the exit code | 2026-11-01 |

<!-- END GENERATED INDEX -->

The same table, browsable, is [docs/README.md](../../../docs/README.md).

## How to read a line range

Every entry is `file — lines — what lives there`. **The line numbers are a
starting point, not an address.** They drift with every commit that touches the
file above them, and nothing regenerates them.

So: jump to roughly that line, then confirm you are in the right place by what the
code says, not by the number. If a range is off by more than a screen or two, fix
it in the page and re-date it — that is a one-line edit and it is how the map
stays worth having.

Line ranges are given at all because the files that matter most here are big:
`src/gate.rs` is 726 lines, `src/promotion.rs` 618 and `src/scan.rs` 580. "It's in <that file>" is not an
answer.

## What this map does not tell you

It tells you **where**, not **why it is dangerous**. Several of the areas below
have failure modes that produce no error message. Those are catalogued
separately, by symptom, in the `repo-maintenance` skill and in
[docs/README.md](../../../docs/README.md). If you are about to change shared state
or anything on the code path that decides a report is clean, look there first.

## Keeping it accurate

A map that lies is worse than none, because it sends people confidently to the
wrong file. Two habits keep it honest:

- **Re-date what you touch.** If you worked in an area and the page was right,
  bump `verified:`. If it was wrong, fix it and bump.
- **Add an area when you create one, not later.** A new subsystem with no page is
  invisible; the next person re-derives its shape from scratch.

To add a page, follow the same rules as any other doc — see the `repo-maintenance`
skill. Frontmatter for an area page is `title`, `covers` (what someone would be
looking for, phrased as they would phrase it), and `verified`. Then run
`scripts/gen-docs-index.sh`; the block above is generated and hand edits to it
are overwritten.
