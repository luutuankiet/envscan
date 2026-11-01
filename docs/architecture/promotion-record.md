---
title: The promotion record
covers: envscan promotion add and status, where the record of handled tmp/ files is stored, what each handling and its ref mean, and how status decides a folder is safe to clear
verified: 2026-11-01
---

# The promotion record

Before a `tmp/` topic folder is cleared, every file in it should have been dealt
with: copied into the repo, written up, filed as an issue, or deliberately
dropped. `envscan promotion add` records how one file was handled;
`envscan promotion status <folder>` lists each file's state and answers one
question, `safe_to_clear`. **Every doubt resolves to "not safe"**: a record that
cannot be read is no record, and a commit that cannot be checked has not landed.

Line numbers below are a **starting point, not an address**. Jump roughly there,
confirm by what the code says, and if a range is off by more than a screen, fix
it here and re-date the page.

## Where each step lives

| step | file and lines | what lives there |
|---|---|---|
| handlings and default branches | `src/promotion.rs` 17-23 | `HANDLINGS`, `DEFAULT_BRANCHES` |
| the on-disk record | `src/promotion.rs` 63-84 | `Record`; field order is the contract, `v` is 1 |
| what a ref must be | `src/promotion.rs` 113-134 | `is_hex`, `is_issue`, `check_ref` |
| where the store lives | `src/promotion.rs` 136-141 | `store_path` |
| writing and reading the store | `src/promotion.rs` 143-186 | `append`, `read_store` |
| naming the repo | `src/promotion.rs` 188-235 | `git_command` clears `GIT_DIR` and friends; `locate` names the repo by its root commit |
| add | `src/promotion.rs` 243-299 | `add`, `try_add` |
| has a commit landed | `src/promotion.rs` 344-387 | `Ancestry::landed` |
| status | `src/promotion.rs` 389-531 | `status`, `build_status` |

## Handlings and their refs

| handling | meaning | `--ref` |
|---|---|---|
| `snapshot` | the file was copied into the repo | a full 40-character commit SHA |
| `cache` | rebuildable or passed-through output (a download, generated text); the repo keeps only a pointer to it | a full commit SHA |
| `write-up` | what the file taught was written into a page | a full commit SHA, or `issue:<n>` |
| `discard` | dropped on purpose | none |
| `refuse` | must not be kept anywhere; it is deleted when the folder is cleared | none |

A wrong ref for the handling is a usage error, at `add` time and again when the
store is read back.

## The store

- One file outside every repo: `~/.local/state/envscan/promotions.jsonl`, so a
  clone that is moved or re-cloned keeps its record. The directory is created
  `0700` and the file `0600`.
- **Append-only.** Each record is one JSON line written in a single `O_APPEND`
  write with a leading newline, so a line torn by an earlier crash cannot swallow
  the next one, and concurrent writers do not interleave. Nothing rewrites or
  deletes a line; the latest record for a path wins.
- A record names its repo by the repo's root commit SHA, not by a path. A
  shallow clone or a repo with no commits cannot be named, so `add` records
  nothing there (exit 2).
- An unparseable or invalid line is skipped and counted in `skipped_lines`.

## add

`envscan promotion add <file> --sha256 <digest> --handling <h> [--ref <r>]`
hashes the file and refuses (exit 3) if the digest differs from the one given:
a file that changed since it was reviewed goes back for review. Only regular
files inside the work tree can be recorded.

## status

`status` exits 0 with the verdict in `safe_to_clear` whichever way it went, and
3 on a usage or IO error or an unreadable file. The folder is **not** safe to
clear when any of these holds, each reported as a line in `reasons`:

- a file has no record, or changed since its record;
- the repo cannot be named;
- the folder is empty, or holds a nested clone (move it to `tmp/refs/`);
- a file or directory cannot be read or listed;
- a recorded commit SHA is not an ancestor of `origin/HEAD`, else `main`, else
  `master`. A squash merge leaves the original SHA off the branch, so a file
  recorded against it reads as not landed; only a delete by hand overrides that.

`refused_deleted_on_clear` lists the `refuse` files so the caller deletes them
rather than promoting them.

## General rule

Any new check in `status` must add a reason when it cannot reach an answer,
never skip silently. `safe_to_clear` is true only when `reasons` is empty, so a
check that fails quietly turns directly into a deleted file.
