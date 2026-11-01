# Documentation

Every page here is written for a maintainer six months from now who opened
exactly this file from a search result and has nothing else loaded.

This index is generated. Run `scripts/gen-docs-index.sh` after adding or
renaming a page; `--check` fails if it is stale.

<!-- BEGIN GENERATED INDEX -- edit the pages, not this block -->

## Where things live

One page per area of the system. Read before going looking for where
something is implemented.

| page | covers | verified |
|---|---|---|
| [The judgement tier](architecture/judgement-tier.md) | how envscan scan decides between plain and live judgement, where the tier and the vendor key are read from, which lines may be sent to the vendor model, and what happens when judging fails | 2026-11-01 |
| [Known-value matching, hydrate and dehydrate](architecture/known-value-matching.md) | how a value from .env is matched in text, which neighbours count as a word boundary, strict versus loose hits, and how hydrate and dehydrate move text between $KEY and real values | 2026-11-01 |
| [The outbound gate](architecture/outbound-gate.md) | what envscan gate checks before a git push leaves the machine, when a repo counts as opted in, why it denies with no leak found, and how gate install writes the pre-push hook | 2026-11-01 |
| [The promotion record](architecture/promotion-record.md) | envscan promotion add and status, where the record of handled tmp/ files is stored, what each handling and its ref mean, and how status decides a folder is safe to clear | 2026-11-01 |
| [The scan pipeline](architecture/scan-pipeline.md) | where envscan scan finds the .env, decides which files to read, matches, extracts candidates, prints the report and picks the exit code | 2026-11-01 |

## Traps

Failure modes that produce no error message, indexed by the symptom you
would observe. Read before debugging behaviour that is wrong but not
crashing.

_No pages yet._

## Reference

Simply true, and expensive to re-derive.

_No pages yet._

## Decisions

Why the repo is the way it is. A merged decision is immutable -- supersede
it with a new one rather than editing it.

- [Maintainer identifiers live only in a local .env](adr/0001-maintainer-identifiers-live-only-in-a-local-env.md)

<!-- END GENERATED INDEX -->
