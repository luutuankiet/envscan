# envscan

A Rust command line tool that helps agents working on brownfield repos follow best
practice and not commit identifiable or sensitive information. It matches known values
from a local `.env`, extracts broad candidates, and can ask a vendor model to judge them.

## Hard constraints

- **This repo is public with no private backstop.** No home paths, host names, account
  emails, employer or client names, or `.env` values in any file, commit or comment.
  Test fixtures use invented names checked to be unregistered.
- **`.env` holds real values; never print or copy them.** Report key names and lengths
  only. API keys do not belong in it. Meaning lives in `.env.example`.
- **Scan against this repo's `.env` before anything is committed or posted**, and check
  values under 3 characters by hand.
- **No agent attribution in commits, pull requests, issues or release notes.** Commits
  use the account's noreply address, set in this clone's git config; set it in any new one.
- **A report never contains a value outside `--full`.** Known-value hits print by key.
- **Published text names one specific sensitive thing by a bare `$KEY`, never by a prose
  description.** `envscan hydrate` resolves it. The scanner cannot catch a stand-in.

## Layout

```
AGENTS.md      always in context, keep it under 4 KB     CLAUDE.md = @AGENTS.md
docs/          prose, indexed in docs/README.md          .claude/  the two index skills
scripts/       repo tooling                              .env.example  what each key means
src/           the crate: cli, env, matcher, walker, extract, scan, report, hydrate, exit
tests/         the binary as a caller sees it
```

## Check commands

```sh
scripts/gen-docs-index.sh --check   # fail if a generated index is stale
cargo test                          # unit tests plus the binary end to end
```

## Documentation

Indexed in [docs/README.md](docs/README.md). Every page is self-contained: it
assumes you opened that one file and have nothing else loaded.

| where | what | read it |
|---|---|---|
| [architecture/](docs/architecture/) | where behaviour lives, one page per area | before going looking for something |
| [traps/](docs/traps/) | failure modes with no error message, indexed by symptom | before debugging something wrong but not crashing |
| [reference/](docs/reference/) | simply true, expensive to re-derive | when you need the detail |
| [adr/](docs/adr/) | why the repo is the way it is | before changing something that looks odd |

<!-- Standard block. Everything above belongs to this project; everything below is
     the pointer every repo laid out this way carries. -->

## Before you wrap up

Leave the repo holding what this session cost you to find out. Four rules.

1. **Sort it, and expect most of it to go nowhere.** A next action is an issue. A
   durable, expensive-to-re-derive fact is a page. A choice that was hard to
   reverse, surprising without context and a real trade-off is a decision record
   under `docs/adr/`. Status, dates, version pins and plans are none of those:
   delete them.
2. **A doc is the last resort.** Type error → test → comment at the site → doc.
   Name the single line you would have commented instead; if you can name it,
   comment it and stop.
3. **Verify against running code before writing, and date the page `verified:`.**
   Anything remembered from earlier in the session is stale until re-read. Deleting
   a draft because the problem is already fixed is a success.
4. **Append, never rewrite.** Supersede a merged decision record with a new one
   naming what it replaces. A trap filename is an identifier quoted elsewhere:
   edit the body, never the name.

Then run `scripts/gen-docs-index.sh`. Never hand-maintain an index.
