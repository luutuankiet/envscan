//! `envscan gate` end to end: the real binary, hook JSON on stdin, `--pre-push` lines, and
//! `gate install`, in temp git repos pushing to a local bare remote. Every value is invented.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::TempDir;

const PLANTED: &str = "zephyrquartz7731";
const SOFT: &str = "bramble";
const NEIGHBOUR: &str = "thistle";

const EXAMPLE: &str = "\
# what: a token planted for the tests
PLANTED_TOKEN=

# what: a value that is also an ordinary word | match: warn
SOFT_WORD=

# what: another ordinary word, with no marker
NEIGHBOUR_WORD=
";

fn env_file() -> String {
    format!("PLANTED_TOKEN={PLANTED}\nSOFT_WORD={SOFT}\nNEIGHBOUR_WORD={NEIGHBOUR}\n")
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn denied(&self) -> bool {
        self.code == 2 && self.stderr.contains("envscan gate: denied")
    }
}

struct Lab {
    _dir: TempDir,
    home: PathBuf,
    repo: PathBuf,
    worktree: PathBuf,
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_envscan")
}

/// PATH with the built binary first, so a pre-push hook's `command -v envscan` finds it.
fn path_with_bin() -> String {
    let dir = Path::new(bin()).parent().unwrap();
    format!("{}:{}", dir.display(), std::env::var("PATH").unwrap_or_default())
}

fn envscan(home: &Path, cwd: &Path, args: &[&str], stdin: &str) -> Run {
    let mut child = Command::new(bin())
        .args(args)
        .current_dir(cwd)
        .env("HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    Run {
        code: out.status.code().expect("exited, not signalled"),
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

fn git_run(home: &Path, cwd: &Path, args: &[&str]) -> Run {
    let out = Command::new("git")
        .args(["-c", "user.name=fixture", "-c", "user.email=fixture"])
        .args(args)
        .current_dir(cwd)
        .env("HOME", home)
        .env("PATH", path_with_bin())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    Run {
        code: out.status.code().expect("exited, not signalled"),
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

fn git(home: &Path, cwd: &Path, args: &[&str]) -> String {
    let run = git_run(home, cwd, args);
    assert_eq!(run.code, 0, "git {args:?}: {}", run.stderr);
    run.stdout.trim().to_string()
}

/// A repo on `main` with `.env` ignored, one commit pushed to a local bare remote, and a
/// linked worktree on `feature`. `.env` and `.env.example` are written by the caller.
fn bare_lab() -> Lab {
    let dir = TempDir::new().unwrap();
    let home = dir.path().join("home");
    let repo = dir.path().join("repo");
    let remote = dir.path().join("remote.git");
    let worktree = dir.path().join("wt");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&repo).unwrap();
    git(&home, dir.path(), &["init", "-q", "--bare", remote.to_str().unwrap()]);
    git(&home, &repo, &["init", "-q"]);
    git(&home, &repo, &["symbolic-ref", "HEAD", "refs/heads/main"]);
    fs::write(repo.join(".gitignore"), ".env\ntmp\n").unwrap();
    git(&home, &repo, &["add", ".gitignore"]);
    git(&home, &repo, &["commit", "-q", "-m", "first"]);
    git(&home, &repo, &["remote", "add", "origin", remote.to_str().unwrap()]);
    git(&home, &repo, &["push", "-q", "origin", "main"]);
    git(&home, &repo, &["worktree", "add", "-q", "-b", "feature", worktree.to_str().unwrap()]);
    git(&home, &worktree, &["push", "-q", "origin", "feature"]);
    Lab { _dir: dir, home, repo, worktree }
}

/// The opted-in lab: `.env` and `.env.example` in the main checkout only, as in real use;
/// the worktree finds them through the shared git directory.
fn lab() -> Lab {
    let lab = bare_lab();
    fs::write(lab.repo.join(".env"), env_file()).unwrap();
    fs::write(lab.repo.join(".env.example"), EXAMPLE).unwrap();
    git(&lab.home, &lab.repo, &["add", ".env.example"]);
    git(&lab.home, &lab.repo, &["commit", "-q", "-m", "key list"]);
    git(&lab.home, &lab.repo, &["push", "-q", "origin", "main"]);
    lab
}

fn json_str(s: &str) -> String {
    serde_json::Value::String(s.to_string()).to_string()
}

fn bash_hook(cwd: &Path, command: &str) -> String {
    format!(
        r#"{{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":{},"tool_input":{{"command":{}}}}}"#,
        json_str(&cwd.to_string_lossy()),
        json_str(command)
    )
}

fn mcp_hook(cwd: &Path, tool: &str, input: serde_json::Value) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "cwd": cwd.to_string_lossy(),
        "tool_input": input,
    })
    .to_string()
}

fn gate(lab: &Lab, cwd: &Path, hook: &str) -> Run {
    envscan(&lab.home, cwd, &["gate"], hook)
}

fn gate_bash(lab: &Lab, cwd: &Path, command: &str) -> Run {
    gate(lab, cwd, &bash_hook(cwd, command))
}

/// Both checkouts every outbound case runs from.
fn checkouts(lab: &Lab) -> [(&'static str, PathBuf); 2] {
    [("main checkout", lab.repo.clone()), ("worktree", lab.worktree.clone())]
}

fn reset(lab: &Lab, cwd: &Path) {
    git(&lab.home, cwd, &["reset", "-q", "--hard"]);
    git(&lab.home, cwd, &["clean", "-q", "-fd"]);
}

fn assert_denied(run: &Run, key: &str, what: &str) {
    assert!(run.denied(), "{what}: expected a deny, got {} / {}", run.code, run.stderr);
    assert!(run.stderr.contains(key), "{what}: the reason should name {key}: {}", run.stderr);
    for value in [PLANTED, SOFT, NEIGHBOUR] {
        assert!(!run.stderr.contains(value), "{what}: the reason must never print a value");
    }
}

fn assert_clean(run: &Run, what: &str) {
    assert_eq!(run.code, 0, "{what}: expected a pass: {}", run.stderr);
}

// ── the soft warn marker ───────────────────────────────────────────────────────────────────

#[test]
fn a_warn_key_passes_commit_and_push_while_its_unmarked_neighbour_denies() {
    let lab = lab();
    for (place, cwd) in checkouts(&lab) {
        // Commit: the warn word passes with a warning naming its key.
        fs::write(cwd.join("notes.txt"), format!("a {SOFT} hedge\n")).unwrap();
        let run = gate_bash(&lab, &cwd, "git add notes.txt && git commit -m 'add notes'");
        assert_clean(&run, place);
        assert!(run.stderr.contains("warning") && run.stderr.contains("SOFT_WORD"), "{place}: {}", run.stderr);
        assert!(!run.stderr.contains(SOFT), "{place}: the warning must name the key, not the value");

        // The neighbour, one block below without the marker, denies.
        fs::write(cwd.join("other.txt"), format!("a {NEIGHBOUR} patch\n")).unwrap();
        let run = gate_bash(&lab, &cwd, "git add other.txt && git commit -m 'add other'");
        assert_denied(&run, "NEIGHBOUR_WORD", place);
        assert!(!run.stderr.contains("SOFT_WORD,") && !run.stderr.contains(": SOFT_WORD."), "{place}: {}", run.stderr);
        fs::remove_file(cwd.join("other.txt")).unwrap();

        // Push: commit the warn word for real, then the push passes with a warning.
        git(&lab.home, &cwd, &["add", "notes.txt"]);
        git(&lab.home, &cwd, &["commit", "-q", "-m", &format!("the {SOFT} hedge")]);
        let run = gate_bash(&lab, &cwd, "git push");
        assert_clean(&run, place);
        assert!(run.stderr.contains("SOFT_WORD"), "{place}: {}", run.stderr);

        // ... and so does git's own pre-push hook, on a real push.
        assert_clean(&envscan(&lab.home, &cwd, &["gate", "install"], ""), place);
        let branch = git(&lab.home, &cwd, &["branch", "--show-current"]);
        let push = git_run(&lab.home, &cwd, &["push", "-q", "origin", &branch]);
        assert_eq!(push.code, 0, "{place}: a warn word must not block a push: {}", push.stderr);
        assert!(push.stderr.contains("SOFT_WORD"), "{place}: {}", push.stderr);

        // The neighbour in a commit blocks the real push.
        fs::write(cwd.join("other.txt"), format!("a {NEIGHBOUR} patch\n")).unwrap();
        git(&lab.home, &cwd, &["add", "other.txt"]);
        git(&lab.home, &cwd, &["commit", "-q", "-m", "other"]);
        assert_denied(&gate_bash(&lab, &cwd, "git push"), "NEIGHBOUR_WORD", place);
        let push = git_run(&lab.home, &cwd, &["push", "-q", "origin", &branch]);
        assert_ne!(push.code, 0, "{place}: the pre-push hook should have refused");
        assert!(push.stderr.contains("NEIGHBOUR_WORD"), "{place}: {}", push.stderr);
        git(&lab.home, &cwd, &["reset", "-q", "--hard", "HEAD~1"]);
    }
}

#[test]
fn a_loose_hit_on_a_warn_key_neither_warns_nor_denies() {
    let lab = lab();
    let cwd = &lab.repo;
    fs::write(cwd.join("notes.txt"), format!("x{SOFT}s\n")).unwrap();
    let run = gate_bash(&lab, cwd, "git add notes.txt && git commit -m notes");
    assert_clean(&run, "loose warn hit");
    assert!(!run.stderr.contains("SOFT_WORD"), "{}", run.stderr);
}

#[test]
fn scan_reports_warn_keys_apart_from_leaks() {
    let lab = lab();
    fs::write(lab.repo.join("notes.txt"), format!("a {SOFT} hedge\n")).unwrap();
    let run = envscan(&lab.home, &lab.repo, &["scan", "--json", "--known-only", "notes.txt"], "");
    assert_eq!(run.code, 0, "a warn hit never changes the exit code: {}", run.stderr);
    let report: serde_json::Value = serde_json::from_str(&run.stdout).unwrap();
    assert_eq!(report["leaks"].as_array().unwrap().len(), 0);
    let warnings = report["warnings"].as_array().unwrap();
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0]["key"], "SOFT_WORD");
    assert!(warnings[0]["strict"].as_u64().unwrap() >= 1);
}

// ── a planted value, every way out ────────────────────────────────────────────────────────

#[test]
fn a_planted_value_is_denied_through_git_commit() {
    let lab = lab();
    for (place, cwd) in checkouts(&lab) {
        // In a tracked change.
        fs::write(cwd.join(".gitignore"), format!(".env\ntmp\n# {PLANTED}\n")).unwrap();
        assert_denied(&gate_bash(&lab, &cwd, "git commit -am 'tidy'"), "PLANTED_TOKEN", place);
        reset(&lab, &cwd);
        // In an untracked file, and in an untracked file's name.
        fs::write(cwd.join("new.txt"), format!("{PLANTED}\n")).unwrap();
        assert_denied(&gate_bash(&lab, &cwd, "git add . && git commit -m new"), "PLANTED_TOKEN", place);
        reset(&lab, &cwd);
        fs::write(cwd.join(format!("{PLANTED}.txt")), "x\n").unwrap();
        assert_denied(&gate_bash(&lab, &cwd, "git add . && git commit -m new"), "PLANTED_TOKEN", place);
        reset(&lab, &cwd);
        // In the message, upper-cased, and URL-encoded.
        let upper = PLANTED.to_uppercase();
        assert_denied(&gate_bash(&lab, &cwd, &format!("git commit --allow-empty -m 'see {upper}'")), "PLANTED_TOKEN", place);
        let encoded = "zephyr%71uartz7731";
        assert_denied(&gate_bash(&lab, &cwd, &format!("git commit --allow-empty -m 'see {encoded}'")), "PLANTED_TOKEN", place);
        // In a -F file.
        fs::write(cwd.join("msg.txt"), format!("see {PLANTED}\n")).unwrap();
        assert_denied(&gate_bash(&lab, &cwd, "git commit --allow-empty -F msg.txt"), "PLANTED_TOKEN", place);
        fs::remove_file(cwd.join("msg.txt")).unwrap();
        // Prefixes are seen through.
        assert_denied(&gate_bash(&lab, &cwd, &format!("rtk git commit --allow-empty -m 'see {PLANTED}'")), "PLANTED_TOKEN", place);
        // A clean commit passes silently.
        fs::write(cwd.join("ok.txt"), "nothing to see\n").unwrap();
        let run = gate_bash(&lab, &cwd, "git add ok.txt && git commit -m 'add ok'");
        assert_clean(&run, place);
        assert_eq!(run.stderr, "", "{place}");
        reset(&lab, &cwd);
    }
}

#[test]
fn a_planted_value_is_denied_through_git_push_and_pre_push() {
    let lab = lab();
    assert_clean(&envscan(&lab.home, &lab.repo, &["gate", "install"], ""), "install");
    for (place, cwd) in checkouts(&lab) {
        let branch = git(&lab.home, &cwd, &["branch", "--show-current"]);
        let base = git(&lab.home, &cwd, &["rev-parse", "HEAD"]);
        fs::write(cwd.join("data.txt"), format!("{PLANTED}\n")).unwrap();
        git(&lab.home, &cwd, &["add", "data.txt"]);
        git(&lab.home, &cwd, &["commit", "-q", "-m", "data"]);
        let head = git(&lab.home, &cwd, &["rev-parse", "HEAD"]);

        // The hook judges `git push` before it runs.
        assert_denied(&gate_bash(&lab, &cwd, "git push"), "PLANTED_TOKEN", place);
        assert_denied(&gate_bash(&lab, &cwd, &format!("git push origin {branch}")), "PLANTED_TOKEN", place);

        // `--pre-push` run directly, with git's own line shape.
        let line = format!("refs/heads/{branch} {head} refs/heads/{branch} {base}\n");
        let run = envscan(&lab.home, &cwd, &["gate", "--pre-push", "origin", "unused-url"], &line);
        assert_denied(&run, "PLANTED_TOKEN", place);
        // A new remote branch: the range runs against every remote-tracking ref.
        let zero = "0".repeat(40);
        let line = format!("refs/heads/{branch} {head} refs/heads/new-{branch} {zero}\n");
        assert_denied(&envscan(&lab.home, &cwd, &["gate", "--pre-push"], &line), "PLANTED_TOKEN", place);
        // The pushed part alone is clean.
        let line = format!("refs/heads/{branch} {base} refs/heads/{branch} {base}\n");
        assert_clean(&envscan(&lab.home, &cwd, &["gate", "--pre-push"], &line), place);

        // A real `git push` stops in the installed hook, and the remote is unchanged.
        let push = git_run(&lab.home, &cwd, &["push", "-q", "origin", &branch]);
        assert_ne!(push.code, 0, "{place}: the push should have been refused");
        assert!(push.stderr.contains("envscan gate: denied") && push.stderr.contains("PLANTED_TOKEN"), "{place}: {}", push.stderr);
        assert_eq!(git(&lab.home, &cwd, &["rev-parse", &format!("origin/{branch}")]), base, "{place}");

        // A planted value in an author name is caught too.
        git(&lab.home, &cwd, &["reset", "-q", "--hard", &base]);
        git(&lab.home, &cwd, &["commit", "-q", "--allow-empty", "-m", "x", "--author", &format!("{PLANTED} <fixture>")]);
        assert_denied(&gate_bash(&lab, &cwd, "git push"), "PLANTED_TOKEN", place);
        git(&lab.home, &cwd, &["reset", "-q", "--hard", &base]);
    }
}

#[test]
fn a_planted_value_is_denied_through_gh_body_and_body_file() {
    let lab = lab();
    for (place, cwd) in checkouts(&lab) {
        let body = format!("gh issue create --title t --body 'found {PLANTED} here'");
        assert_denied(&gate_bash(&lab, &cwd, &body), "PLANTED_TOKEN", place);
        let comment = format!("gh pr comment 3 --body \"found {PLANTED} here\"");
        assert_denied(&gate_bash(&lab, &cwd, &comment), "PLANTED_TOKEN", place);

        fs::write(cwd.join("body.md"), format!("found {PLANTED} here\n")).unwrap();
        assert_denied(&gate_bash(&lab, &cwd, "gh issue create --title t --body-file body.md"), "PLANTED_TOKEN", place);
        assert_denied(&gate_bash(&lab, &cwd, "gh pr create --title t --body-file=body.md"), "PLANTED_TOKEN", place);
        assert_denied(&gate_bash(&lab, &cwd, "gh api repos/o/r/issues -F body=@body.md"), "PLANTED_TOKEN", place);
        // A file the gate cannot read is refused rather than passed.
        assert!(gate_bash(&lab, &cwd, "gh issue create --title t --body-file missing.md").denied(), "{place}");

        fs::write(cwd.join("body.md"), "uses $PLANTED_TOKEN, written as a variable\n").unwrap();
        assert_clean(&gate_bash(&lab, &cwd, "gh issue create --title t --body-file body.md"), place);
        assert_clean(&gate_bash(&lab, &cwd, "gh issue comment 3 --body 'uses $PLANTED_TOKEN'"), place);
        fs::remove_file(cwd.join("body.md")).unwrap();
    }
}

#[test]
fn a_planted_value_is_denied_through_an_mcp_gh_call() {
    let lab = lab();
    let tool = "mcp__claude_ai_proxy__github-gh-cli__gh";
    for (place, cwd) in checkouts(&lab) {
        let input = serde_json::json!({ "args": ["issue", "create", "--title", "t", "--body", format!("found {PLANTED}")] });
        assert_denied(&gate(&lab, &cwd, &mcp_hook(&cwd, tool, input)), "PLANTED_TOKEN", place);
        let input = serde_json::json!({ "endpoint": "repos/o/r/issues", "fields": { "body": format!("x {PLANTED} y") } });
        assert_denied(&gate(&lab, &cwd, &mcp_hook(&cwd, "mcp__gh-cli__gh_api", input)), "PLANTED_TOKEN", place);
        // A file the payload names is read.
        fs::write(cwd.join("body.md"), format!("found {PLANTED}\n")).unwrap();
        let input = serde_json::json!({ "args": "issue create --title t --body-file body.md" });
        assert_denied(&gate(&lab, &cwd, &mcp_hook(&cwd, tool, input)), "PLANTED_TOKEN", place);
        fs::remove_file(cwd.join("body.md")).unwrap();
        // Read tools pass, whatever they carry.
        let input = serde_json::json!({ "pattern": PLANTED });
        assert_clean(&gate(&lab, &cwd, &mcp_hook(&cwd, "mcp__claude_ai_proxy__github-gh-cli__grep", input)), place);
        // A clean call passes.
        let input = serde_json::json!({ "args": "issue create --title t --body 'uses $PLANTED_TOKEN'" });
        assert_clean(&gate(&lab, &cwd, &mcp_hook(&cwd, tool, input)), place);
    }
}

// ── denied outright, and exempt ───────────────────────────────────────────────────────────

#[test]
fn expansions_beside_an_outbound_verb_deny_and_literal_text_passes() {
    let lab = lab();
    let cwd = &lab.repo;
    for command in [
        "git commit --allow-empty -m \"$MSG\"",
        "git commit --allow-empty -m \"$(date)\"",
        "eval git push",
        "sh -c 'git push'",
        "git push --no-verify",
        "git -c core.hooksPath=/dev/null push",
        "gh issue create --title t --body-file - <<EOF\nplain\nEOF",
    ] {
        assert!(gate_bash(&lab, cwd, command).denied(), "{command}");
    }
    for command in [
        "git commit --allow-empty -m 'uses $PLANTED_TOKEN'",
        "git commit --allow-empty -m \"$(cat <<'EOF'\nuses $PLANTED_TOKEN\nEOF\n)\"",
        "gh issue comment 3 --body-file - <<'EOF'\nuses $PLANTED_TOKEN\nEOF",
        "ls $HOME",
        "git status",
    ] {
        assert_clean(&gate_bash(&lab, cwd, command), command);
    }
    // A literal heredoc is still scanned.
    let command = format!("gh issue comment 3 --body-file - <<'EOF'\nfound {PLANTED}\nEOF");
    assert_denied(&gate_bash(&lab, cwd, &command), "PLANTED_TOKEN", "heredoc body");
}

// ── incomplete protection, and repos that are not opted in ───────────────────────────────

#[test]
fn a_half_filled_env_denies_naming_the_keys() {
    let lab = lab();
    // A key the example lists is missing, and another is empty.
    fs::write(lab.repo.join(".env"), format!("PLANTED_TOKEN={PLANTED}\nSOFT_WORD=\n")).unwrap();
    for (place, cwd) in checkouts(&lab) {
        let run = gate_bash(&lab, &cwd, "git commit --allow-empty -m clean");
        assert!(run.denied(), "{place}: {}", run.stderr);
        assert!(run.stderr.contains("incomplete"), "{place}: {}", run.stderr);
        assert!(run.stderr.contains("NEIGHBOUR_WORD") && run.stderr.contains("SOFT_WORD"), "{place}: {}", run.stderr);
        let input = serde_json::json!({ "args": "issue create --title t --body clean" });
        assert!(gate(&lab, &cwd, &mcp_hook(&cwd, "mcp__gh-cli__gh", input)).denied(), "{place}");
        let base = git(&lab.home, &cwd, &["rev-parse", "HEAD"]);
        let line = format!("refs/heads/x {base} refs/heads/x {base}\n");
        assert!(envscan(&lab.home, &cwd, &["gate", "--pre-push"], &line).denied(), "{place}");
        // Non-outbound calls are not judged at all.
        assert_clean(&gate_bash(&lab, &cwd, "git status"), place);
    }
}

#[test]
fn an_env_with_no_values_denies() {
    let lab = lab();
    fs::write(lab.repo.join(".env"), "# nothing yet\n").unwrap();
    fs::write(lab.repo.join(".env.example"), "# no keys listed\n").unwrap();
    let run = gate_bash(&lab, &lab.repo, "git commit --allow-empty -m clean");
    assert!(run.denied() && run.stderr.contains("0 rules"), "{}", run.stderr);
}

#[test]
fn an_example_with_no_env_denies() {
    let lab = lab();
    fs::remove_file(lab.repo.join(".env")).unwrap();
    for (place, cwd) in checkouts(&lab) {
        let run = gate_bash(&lab, &cwd, "git commit --allow-empty -m clean");
        assert!(run.denied(), "{place}: {}", run.stderr);
        assert!(run.stderr.contains("PLANTED_TOKEN"), "{place}: {}", run.stderr);
    }
}

#[test]
fn no_env_and_no_example_passes_silently() {
    let lab = bare_lab();
    for (place, cwd) in checkouts(&lab) {
        fs::write(cwd.join("new.txt"), format!("{PLANTED}\n")).unwrap();
        for command in ["git add . && git commit -m new", "git push", "gh issue create --title t --body x"] {
            let run = gate_bash(&lab, &cwd, command);
            assert_eq!((run.code, run.stderr.as_str()), (0, ""), "{place}: {command}");
        }
        let input = serde_json::json!({ "args": format!("issue create --body {PLANTED}") });
        let run = gate(&lab, &cwd, &mcp_hook(&cwd, "mcp__gh-cli__gh", input));
        assert_eq!((run.code, run.stderr.as_str()), (0, ""), "{place}: mcp");
        let run = envscan(&lab.home, &cwd, &["gate", "--pre-push"], "");
        assert_eq!((run.code, run.stderr.as_str()), (0, ""), "{place}: pre-push");
        reset(&lab, &cwd);
    }
}

#[test]
fn input_that_is_not_json_denies() {
    let lab = lab();
    assert!(envscan(&lab.home, &lab.repo, &["gate"], "not json").denied());
}

// ── gate install ──────────────────────────────────────────────────────────────────────────

#[test]
fn gate_install_writes_once_refuses_another_hook_and_needs_a_repo() {
    let lab = lab();
    let hook = lab.repo.join(".git/hooks/pre-push");

    let run = envscan(&lab.home, &lab.repo, &["gate", "install"], "");
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(run.stdout.contains("wrote"), "{}", run.stdout);
    let written = fs::read_to_string(&hook).unwrap();
    assert!(written.contains("gate --pre-push"));
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(fs::metadata(&hook).unwrap().permissions().mode() & 0o111, 0o111);

    // Idempotent, from the main checkout or the worktree, which share the hooks directory.
    for cwd in [&lab.repo, &lab.worktree] {
        let run = envscan(&lab.home, cwd, &["gate", "install"], "");
        assert_eq!(run.code, 0, "{}", run.stderr);
        assert!(run.stdout.contains("already installed"), "{}", run.stdout);
    }

    // A different hook is never overwritten; the line to add is printed.
    fs::write(&hook, "#!/bin/sh\nexit 0\n").unwrap();
    let run = envscan(&lab.home, &lab.repo, &["gate", "install"], "");
    assert_eq!(run.code, 2, "{}", run.stderr);
    assert!(run.stderr.contains("refused") && run.stderr.contains("envscan gate --pre-push"), "{}", run.stderr);
    assert_eq!(fs::read_to_string(&hook).unwrap(), "#!/bin/sh\nexit 0\n");

    // A tracked hooks directory is refused too.
    let other = bare_lab();
    fs::create_dir_all(other.repo.join("githooks")).unwrap();
    fs::write(other.repo.join("githooks/pre-commit"), "#!/bin/sh\n").unwrap();
    git(&other.home, &other.repo, &["add", "githooks"]);
    git(&other.home, &other.repo, &["commit", "-q", "-m", "hooks"]);
    git(&other.home, &other.repo, &["config", "core.hooksPath", "githooks"]);
    let run = envscan(&other.home, &other.repo, &["gate", "install"], "");
    assert_eq!(run.code, 2, "{}", run.stderr);
    assert!(!other.repo.join("githooks/pre-push").exists());

    // Not a repo.
    let outside = TempDir::new().unwrap();
    let run = envscan(&lab.home, outside.path(), &["gate", "install"], "");
    assert_eq!(run.code, 3, "{}", run.stderr);
}
