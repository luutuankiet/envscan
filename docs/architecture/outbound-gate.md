---
title: The outbound gate
covers: what envscan gate checks before a git push leaves the machine, when a repo counts as opted in, why it denies with no leak found, and how gate install writes the pre-push hook
verified: 2026-11-07
---

# The outbound gate

`envscan gate --pre-push` is a git pre-push hook. It reads the ref lines git
passes on stdin, scans everything that would leave the machine with the push,
and exits 0 to allow it or 2 to deny it with a reason on stderr that names keys,
never values. `envscan gate install` writes that hook into a repo.

**The git pre-push hook is the only live caller.** The binary still has a second
mode, entered when `--pre-push` is absent, that reads a Claude Code PreToolUse
hook's JSON and judges `git commit`, `git push`, `gh` posting verbs and GitHub
MCP tools. Nothing calls it any more: context-lab, which installed that hook,
removed it (context-lab ADR 0016). The help text for `envscan gate`
(`src/cli.rs` 28-31) and the module comment (`src/gate.rs` 1-6) still describe
the PreToolUse caller; that wording is stale and is tracked as an open issue on
this repo.

Line numbers below are a **starting point, not an address**. Jump roughly there,
confirm by what the code says, and if a range is off by more than a screen, fix
it here and re-date the page.

## Where each step lives

| step | file and lines | what lives there |
|---|---|---|
| entry | `src/gate.rs` 46-64 | `run`: `gate install`, then the `--pre-push` path |
| the unused JSON mode | `src/gate.rs` 65-90 | the PreToolUse branch; no live caller |
| opting in | `src/gate.rs` 134-168 | `Gate::load`: finds `.env` and `.env.example` the same way `scan` does |
| refusing to run blind | `src/gate.rs` 170-181 | `preflight` |
| the verdict | `src/gate.rs` 237-275 | `verdict`, `check`, `check_once`: percent-decoded text is checked too |
| what a push carries | `src/gate.rs` 314-344 | `check_range`: patches, file names, messages, then author and committer field by field |
| reading the ref lines | `src/gate.rs` 346-372 | `pre_push`: ref names, annotated tags, the commit range per ref |
| writing the hook | `src/gate.rs` 17-21, 639-680 | `HOOK_SCRIPT` and `install` |

## When the gate applies

- **A repo with no `.env` and no `.env.example` is not opted in**, and every push
  passes (exit 0). This is what lets the hook sit in any repo harmlessly.
- Once either file exists, `preflight` denies before scanning when a key listed
  in `.env.example` has no value in `.env`, or when no rule loaded at all. A gate
  with missing rules would pass text it should stop, so "protection is
  incomplete" is a denial, not a warning.
- Values of 1 or 2 characters, which are not rules for `scan`, are checked here
  as strict whole-word hits only.
- A key in an `.env.example` block whose `# what:` line ends `| match: warn`
  (`src/env.rs` 59-90) produces a stderr warning on a strict hit and never a
  denial.

## What a push is checked for

For each ref line git passes:

- the local and remote ref names;
- an annotated tag's own text;
- every commit in the range not already on the remote (a new branch is checked
  against everything not on any remote): its patch, the names of the files it
  touches, the author and committer name and email, and the message.

**The pusher's own identity is exempt.** An author or committer name or email that
equals this clone's `git config user.name` or `user.email` exactly is not checked,
even when `.env` holds the same value: a repo whose `.env` lists the operator's
email for a service (a certificate or DNS account) would otherwise deny every push
the operator makes. The comparison is per field and exact, so an identity that
only contains a known value, or someone else's identity, is still checked, and the
message and patch are checked whoever wrote them.

A push that adds a binary file is denied: the gate cannot scan one, so binaries
are pushed by the operator by hand. Any git command that fails while reading the
push denies it; an unreadable push is never a clean one.

## gate install

`envscan gate install` writes the pre-push hook at `git rev-parse --git-path
hooks`. The hook finds `envscan` on `PATH`, else `~/.local/bin/envscan`. It exits
0 when the hook is written or the same hook is already there, and refuses (exit 2)
when a different pre-push hook exists or `core.hooksPath` points at a tracked
directory, printing the one line to add to the existing hook instead. It never
overwrites a hook it did not write.

## General rule

Every path through the gate that cannot finish its reading must deny with a
reason. A gate that allows on error looks identical to a gate that checked and
found nothing, and the person pushing has no way to tell them apart.
