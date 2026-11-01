//! `promotion add` and `promotion status` as a caller sees them, on real git repos in temp
//! directories. Names and contents are invented.

use serde_json::Value;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

const TOPIC: &str = "tmp/20261101/topic";

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

struct Lab {
    _dir: TempDir,
    home: PathBuf,
    repo: PathBuf,
}

fn envscan(home: &Path, cwd: &Path, args: &[&str]) -> Run {
    let out = Command::new(env!("CARGO_BIN_EXE_envscan"))
        .args(args)
        .current_dir(cwd)
        .env("HOME", home)
        .output()
        .unwrap();
    Run {
        code: out.status.code().expect("exited, not signalled"),
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

fn git(cwd: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(["-c", "user.name=fixture", "-c", "user.email=fixture"])
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn commit(repo: &Path, name: &str) -> String {
    fs::write(repo.join(name), name).unwrap();
    git(repo, &["add", name]);
    git(repo, &["commit", "-q", "-m", name]);
    git(repo, &["rev-parse", "HEAD"])
}

fn init(repo: &Path) {
    fs::create_dir_all(repo).unwrap();
    git(repo, &["init", "-q"]);
    git(repo, &["symbolic-ref", "HEAD", "refs/heads/main"]);
}

/// A repo on `main` with one commit, ignoring `tmp/` as promoted repos do, and an empty topic.
fn lab() -> Lab {
    let dir = TempDir::new().unwrap();
    let home = dir.path().join("home");
    let repo = dir.path().join("repo");
    fs::create_dir_all(&home).unwrap();
    init(&repo);
    fs::write(repo.join(".gitignore"), "tmp\n").unwrap();
    git(&repo, &["add", ".gitignore"]);
    git(&repo, &["commit", "-q", "-m", "first"]);
    fs::create_dir_all(repo.join(TOPIC)).unwrap();
    Lab { _dir: dir, home, repo }
}

fn sha256_of(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

impl Lab {
    fn write(&self, name: &str, body: &str) -> (String, String) {
        let path = format!("{TOPIC}/{name}");
        let full = self.repo.join(&path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, body).unwrap();
        (path, sha256_of(body.as_bytes()))
    }

    fn run(&self, args: &[&str]) -> Run {
        envscan(&self.home, &self.repo, args)
    }

    fn add(&self, path: &str, sha: &str, handling: &str, reference: Option<&str>) -> Run {
        let mut args = vec!["promotion", "add", path, "--sha256", sha, "--handling", handling];
        if let Some(r) = reference {
            args.extend(["--ref", r]);
        }
        self.run(&args)
    }

    fn status(&self) -> Value {
        status_of(&self.home, &self.repo, TOPIC)
    }

    fn store(&self) -> PathBuf {
        self.home.join(".local/state/envscan/promotions.jsonl")
    }
}

fn status_of(home: &Path, cwd: &Path, folder: &str) -> Value {
    let run = envscan(home, cwd, &["promotion", "status", folder, "--json"]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    serde_json::from_str(&run.stdout).unwrap()
}

fn file<'a>(status: &'a Value, path: &str) -> &'a Value {
    status["files"].as_array().unwrap().iter().find(|f| f["path"] == path).unwrap_or_else(|| panic!("{path}: {status}"))
}

fn reasons(status: &Value) -> String {
    status["reasons"].to_string()
}

#[test]
fn a_record_has_the_exact_shape_and_private_modes() {
    let lab = lab();
    let head = git(&lab.repo, &["rev-parse", "HEAD"]);
    let (path, sha) = lab.write("a.py", "print(1)\n");
    let run = lab.add(&path, &sha, "snapshot", Some(&head));
    assert_eq!(run.code, 0, "{}", run.stderr);

    let raw = fs::read_to_string(lab.store()).unwrap();
    assert!(raw.starts_with('\n') && raw.ends_with('\n'), "{raw:?}");
    let line = raw.trim();
    let at = serde_json::from_str::<Value>(line).unwrap()["at"].as_str().unwrap().to_string();
    assert_eq!(
        line,
        format!(r#"{{"v":1,"repo":"{head}","path":"{path}","sha256":"{sha}","handling":"snapshot","at":"{at}","ref":"{head}"}}"#)
    );
    assert!(at.len() == 20 && at.ends_with('Z') && at.as_bytes()[10] == b'T', "{at}");

    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(lab.store().parent().unwrap()), 0o700);
    assert_eq!(mode(&lab.store()), 0o600);
}

#[test]
fn loose_existing_modes_are_tightened_on_write() {
    let lab = lab();
    let store = lab.store();
    let dir = store.parent().unwrap();
    fs::create_dir_all(dir).unwrap();
    fs::write(&store, "").unwrap();
    fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o644)).unwrap();
    let (path, sha) = lab.write("a.py", "a");
    assert_eq!(lab.add(&path, &sha, "discard", None).code, 0);
    assert_eq!(fs::metadata(dir).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(fs::metadata(&store).unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn eight_concurrent_writers_lose_nothing() {
    const WRITERS: usize = 8;
    const EACH: usize = 40;
    let lab = lab();
    // Long names, so an interleaved write could not pass for two valid lines.
    let long = "n".repeat(180);
    let mut planned = Vec::new();
    for w in 0..WRITERS {
        let mut batch = Vec::new();
        for i in 0..EACH {
            batch.push(lab.write(&format!("w{w}-{i}-{long}.txt"), &format!("{w} {i}")));
        }
        planned.push(batch);
    }
    std::thread::scope(|scope| {
        for batch in &planned {
            let lab = &lab;
            scope.spawn(move || {
                for (path, sha) in batch {
                    let run = lab.add(path, sha, "discard", None);
                    assert_eq!(run.code, 0, "{}", run.stderr);
                }
            });
        }
    });

    let raw = fs::read_to_string(lab.store()).unwrap();
    let lines: Vec<&str> = raw.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), WRITERS * EACH);
    assert!(lines.iter().all(|l| serde_json::from_str::<Value>(l).is_ok()));

    let status = lab.status();
    assert_eq!(status["skipped_lines"], 0);
    let files = status["files"].as_array().unwrap();
    assert_eq!(files.len(), WRITERS * EACH);
    assert!(files.iter().all(|f| f["state"] == "recorded"));
    assert_eq!(status["safe_to_clear"], true, "{}", reasons(&status));
}

#[test]
fn a_torn_tail_then_an_append_leaves_both_neighbours_readable() {
    let lab = lab();
    let (a, a_sha) = lab.write("a.txt", "a");
    let (b, b_sha) = lab.write("b.txt", "b");
    assert_eq!(lab.add(&a, &a_sha, "discard", None).code, 0);

    // A crash mid-write: no newline at the end, and bytes that are not even text.
    let mut bytes = fs::read(lab.store()).unwrap();
    bytes.extend_from_slice(b"{\"v\":1,\"repo\":\"tor\xff");
    fs::write(lab.store(), bytes).unwrap();

    assert_eq!(lab.add(&b, &b_sha, "discard", None).code, 0);
    let status = lab.status();
    assert_eq!(file(&status, &a)["state"], "recorded");
    assert_eq!(file(&status, &b)["state"], "recorded");
    assert_eq!(status["skipped_lines"], 1);
    assert_eq!(status["safe_to_clear"], true, "{}", reasons(&status));
}

#[test]
fn a_moved_clone_keeps_its_record() {
    let lab = lab();
    let head = git(&lab.repo, &["rev-parse", "HEAD"]);
    let (path, sha) = lab.write("a.py", "a");
    assert_eq!(lab.add(&path, &sha, "snapshot", Some(&head)).code, 0);

    let moved = lab.repo.parent().unwrap().join("elsewhere/renamed");
    fs::create_dir_all(moved.parent().unwrap()).unwrap();
    fs::rename(&lab.repo, &moved).unwrap();

    let status = status_of(&lab.home, &moved, TOPIC);
    assert_eq!(file(&status, &path)["state"], "recorded");
    assert_eq!(file(&status, &path)["ref_ok"], true);
    assert_eq!(status["safe_to_clear"], true, "{}", reasons(&status));
}

#[test]
fn a_linked_worktree_shares_the_record_of_its_repo() {
    let lab = lab();
    let tree = lab.repo.parent().unwrap().join("linked");
    git(&lab.repo, &["worktree", "add", "-q", "-b", "side", tree.to_str().unwrap()]);
    let body = "same in both";
    let (path, sha) = lab.write("a.txt", body);
    fs::create_dir_all(tree.join(TOPIC)).unwrap();
    fs::write(tree.join(&path), body).unwrap();

    let run = envscan(&lab.home, &tree, &["promotion", "add", &path, "--sha256", &sha, "--handling", "discard"]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(file(&lab.status(), &path)["state"], "recorded");
}

#[test]
fn a_digest_that_differs_exits_3_and_records_nothing() {
    let lab = lab();
    let (path, _) = lab.write("a.txt", "new text");
    let run = lab.add(&path, &sha256_of(b"text the menu saw"), "discard", None);
    assert_eq!(run.code, 3);
    assert!(run.stderr.contains("back to the menu"), "{}", run.stderr);
    assert!(!lab.store().exists());
}

#[test]
fn bad_arguments_exit_3_and_record_nothing() {
    let lab = lab();
    let (path, sha) = lab.write("a.txt", "a");
    let sha_ref = "a".repeat(40);
    for (digest, handling, reference) in [
        ("abc", "discard", None),
        (sha.as_str(), "invented", None),
        (sha.as_str(), "snapshot", None),
        (sha.as_str(), "cache", Some("issue:3")),
        (sha.as_str(), "write-up", Some("https://example.invalid/3")),
        (sha.as_str(), "refuse", Some(sha_ref.as_str())),
    ] {
        assert_eq!(lab.add(&path, digest, handling, reference).code, 3, "{handling} {reference:?}");
    }
    assert_eq!(lab.add("no/such/file", &sha, "discard", None).code, 3);
    assert_eq!(lab.run(&["promotion", "status", "no/such/folder"]).code, 3);
    assert_eq!(lab.run(&["promotion"]).code, 3);
    assert!(!lab.store().exists());
}

#[test]
fn a_symlink_cannot_be_recorded_and_is_not_followed() {
    let lab = lab();
    let outside = lab.repo.parent().unwrap().join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("target.txt"), "t").unwrap();
    symlink(outside.join("target.txt"), lab.repo.join(TOPIC).join("link.txt")).unwrap();
    symlink(&outside, lab.repo.join(TOPIC).join("linkdir")).unwrap();
    let (path, _) = lab.write("real.txt", "r");

    let linked = format!("{TOPIC}/link.txt");
    assert_eq!(lab.add(&linked, &sha256_of(b"t"), "discard", None).code, 3);

    let status = lab.status();
    assert_eq!(status["files"].as_array().unwrap().len(), 1);
    assert_eq!(file(&status, &path)["state"], "none");
}

#[test]
fn no_commits_exits_2_and_status_lists_all_as_none() {
    let dir = TempDir::new().unwrap();
    let home = dir.path().join("home");
    let repo = dir.path().join("repo");
    fs::create_dir_all(&home).unwrap();
    init(&repo);
    fs::create_dir_all(repo.join("t")).unwrap();
    fs::write(repo.join("t/a.txt"), "a").unwrap();

    let sha = sha256_of(b"a");
    let run = envscan(&home, &repo, &["promotion", "add", "t/a.txt", "--sha256", &sha, "--handling", "discard"]);
    assert_eq!(run.code, 2);
    assert!(run.stderr.contains("no commits"), "{}", run.stderr);
    assert!(!home.join(".local/state/envscan").exists());

    let status = status_of(&home, &repo, "t");
    assert_eq!(file(&status, "t/a.txt")["state"], "none");
    assert_eq!(file(&status, "t/a.txt")["sha256"], sha);
    assert_eq!(status["safe_to_clear"], false);
    assert!(reasons(&status).contains("no commits"), "{status}");
}

#[test]
fn a_shallow_clone_exits_2_even_with_a_record_from_the_full_clone() {
    let lab = lab();
    commit(&lab.repo, "second");
    let (path, sha) = lab.write("a.txt", "a");
    assert_eq!(lab.add(&path, &sha, "discard", None).code, 0);

    let shallow = lab.repo.parent().unwrap().join("shallow");
    let url = format!("file://{}", lab.repo.display());
    git(lab.repo.parent().unwrap(), &["clone", "-q", "--depth", "1", &url, shallow.to_str().unwrap()]);
    fs::create_dir_all(shallow.join(TOPIC)).unwrap();
    fs::write(shallow.join(&path), "a").unwrap();

    let run = envscan(&lab.home, &shallow, &["promotion", "add", &path, "--sha256", &sha, "--handling", "discard"]);
    assert_eq!(run.code, 2);
    assert!(run.stderr.contains("shallow"), "{}", run.stderr);

    let status = status_of(&lab.home, &shallow, TOPIC);
    assert_eq!(file(&status, &path)["state"], "none");
    assert_eq!(status["safe_to_clear"], false);
    assert!(reasons(&status).contains("shallow"), "{status}");
}

#[test]
fn outside_any_repo_status_is_none_and_add_exits_2() {
    let dir = TempDir::new().unwrap();
    let home = dir.path().join("home");
    let plain = dir.path().join("plain");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&plain).unwrap();
    fs::write(plain.join("a.txt"), "a").unwrap();
    let sha = sha256_of(b"a");

    let run = envscan(&home, &plain, &["promotion", "add", "a.txt", "--sha256", &sha, "--handling", "discard"]);
    assert_eq!(run.code, 2, "{}", run.stderr);
    let status = status_of(&home, &plain, ".");
    assert_eq!(status["files"][0]["state"], "none");
    assert_eq!(status["safe_to_clear"], false);
}

#[test]
fn the_last_valid_line_wins_and_another_repos_line_does_not_count() {
    let lab = lab();
    let head = git(&lab.repo, &["rev-parse", "HEAD"]);
    let (path, sha) = lab.write("a.txt", "a");
    assert_eq!(lab.add(&path, &sha, "discard", None).code, 0);
    assert_eq!(lab.add(&path, &sha, "cache", Some(&head)).code, 0);

    // After it come a line of another repo and three that are not valid records.
    let other = "b".repeat(40);
    let at = "2026-11-01T12:00:00Z";
    let lines = [
        format!(r#"{{"v":1,"repo":"{other}","path":"{path}","sha256":"{sha}","handling":"refuse","at":"{at}","ref":null}}"#),
        format!(r#"{{"v":2,"repo":"{head}","path":"{path}","sha256":"{sha}","handling":"refuse","at":"{at}","ref":null}}"#),
        format!(r#"{{"v":1,"repo":"{head}","path":"{path}","sha256":"{sha}","handling":"snapshot","at":"{at}","ref":null}}"#),
        "not json".to_string(),
    ];
    let mut raw = fs::read_to_string(lab.store()).unwrap();
    raw.push_str(&lines.join("\n\n"));
    raw.push('\n');
    fs::write(lab.store(), raw).unwrap();

    let status = lab.status();
    assert_eq!(file(&status, &path)["handling"], "cache");
    assert_eq!(file(&status, &path)["ref"], head.as_str());
    assert_eq!(status["skipped_lines"], 3);
    assert_eq!(status["refused_deleted_on_clear"].as_array().unwrap().len(), 0);
}

#[test]
fn a_changed_file_is_changed_and_not_safe() {
    let lab = lab();
    let (path, sha) = lab.write("a.txt", "a");
    assert_eq!(lab.add(&path, &sha, "discard", None).code, 0);
    assert_eq!(lab.status()["safe_to_clear"], true);

    lab.write("a.txt", "a, edited");
    let status = lab.status();
    assert_eq!(file(&status, &path)["state"], "changed");
    assert_eq!(status["safe_to_clear"], false);
    assert!(reasons(&status).contains("changed"), "{status}");
}

#[test]
fn every_file_counts_ignored_or_secret_named() {
    let lab = lab();
    fs::write(lab.repo.join(".gitignore"), "tmp\n*.log\n").unwrap();
    let (log, _) = lab.write("run.log", "l");
    let (env, _) = lab.write(".env", "K=v");
    let (deep, _) = lab.write("sub/dir/data.csv", "1,2");
    let status = lab.status();
    assert_eq!(status["files"].as_array().unwrap().len(), 3);
    for path in [log, env, deep] {
        assert_eq!(file(&status, &path)["state"], "none");
    }
    assert_eq!(status["safe_to_clear"], false);
}

#[test]
fn a_nested_clone_is_one_none_item_and_never_entered() {
    let lab = lab();
    let nested = lab.repo.join(TOPIC).join("clone");
    init(&nested);
    commit(&nested, "inner.txt");

    let status = lab.status();
    let files = status["files"].as_array().unwrap();
    assert_eq!(files.len(), 1, "{status}");
    let path = format!("{TOPIC}/clone");
    assert_eq!(file(&status, &path)["state"], "none");
    assert_eq!(file(&status, &path)["sha256"], Value::Null);
    assert_eq!(status["safe_to_clear"], false);
    assert!(reasons(&status).contains("move to tmp/refs/"), "{status}");
}

#[test]
fn a_topic_folder_that_is_itself_a_clone_is_one_none_item() {
    let lab = lab();
    let nested = lab.repo.join(TOPIC);
    init(&nested);
    commit(&nested, "inner.txt");

    let status = lab.status();
    assert_eq!(status["files"].as_array().unwrap().len(), 1, "{status}");
    assert_eq!(file(&status, TOPIC)["state"], "none");
    assert_eq!(status["safe_to_clear"], false);
    assert!(reasons(&status).contains("move to tmp/refs/"), "{status}");
}

#[test]
fn an_empty_folder_is_not_safe() {
    let lab = lab();
    let status = lab.status();
    assert_eq!(status["safe_to_clear"], false);
    assert!(reasons(&status).contains("no regular files"), "{status}");
}

#[test]
fn a_file_that_cannot_be_read_exits_3_and_is_not_safe() {
    let lab = lab();
    let (path, _) = lab.write("locked.txt", "l");
    let full = lab.repo.join(&path);
    fs::set_permissions(&full, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read(&full).is_ok() {
        return; // Root reads anything, so there is no failure to observe.
    }
    let run = lab.run(&["promotion", "status", TOPIC, "--json"]);
    assert_eq!(run.code, 3);
    let status: Value = serde_json::from_str(&run.stdout).unwrap();
    assert_eq!(file(&status, &path)["sha256"], Value::Null);
    assert_eq!(status["safe_to_clear"], false);
}

#[test]
fn an_unreadable_store_exits_3_rather_than_reading_as_empty() {
    let lab = lab();
    lab.write("a.txt", "a");
    fs::create_dir_all(lab.store()).unwrap();
    let run = lab.run(&["promotion", "status", TOPIC]);
    assert_eq!(run.code, 3);
    assert!(run.stdout.is_empty(), "{}", run.stdout);
}

#[test]
fn status_writes_nothing() {
    let lab = lab();
    lab.write("a.txt", "a");
    lab.status();
    assert!(!lab.home.join(".local").exists());
}

// Safe to clear against the default branch.

#[test]
fn a_commit_on_a_branch_is_not_safe_until_it_merges() {
    let lab = lab();
    git(&lab.repo, &["switch", "-q", "-c", "promote/topic"]);
    let sha = commit(&lab.repo, "evidence.txt");
    let (path, digest) = lab.write("a.py", "a");
    assert_eq!(lab.add(&path, &digest, "snapshot", Some(&sha)).code, 0);

    let status = lab.status();
    assert_eq!(file(&status, &path)["state"], "recorded");
    assert_eq!(file(&status, &path)["ref_ok"], false);
    assert_eq!(status["safe_to_clear"], false);
    assert!(reasons(&status).contains(&format!("{sha} is not an ancestor of main")), "{status}");

    git(&lab.repo, &["switch", "-q", "main"]);
    git(&lab.repo, &["merge", "-q", "--no-ff", "-m", "merge", "promote/topic"]);
    let status = lab.status();
    assert_eq!(file(&status, &path)["ref_ok"], true);
    assert_eq!(status["safe_to_clear"], true, "{}", reasons(&status));
}

#[test]
fn a_squash_merge_fails_safely() {
    let lab = lab();
    git(&lab.repo, &["switch", "-q", "-c", "promote/topic"]);
    let sha = commit(&lab.repo, "evidence.txt");
    let (path, digest) = lab.write("a.py", "a");
    assert_eq!(lab.add(&path, &digest, "snapshot", Some(&sha)).code, 0);
    git(&lab.repo, &["switch", "-q", "main"]);
    git(&lab.repo, &["merge", "-q", "--squash", "promote/topic"]);
    git(&lab.repo, &["commit", "-q", "-m", "squashed"]);

    let status = lab.status();
    assert_eq!(file(&status, &path)["ref_ok"], false);
    assert_eq!(status["safe_to_clear"], false);
}

#[test]
fn an_unknown_sha_is_not_safe() {
    let lab = lab();
    let (path, digest) = lab.write("a.py", "a");
    let unknown = "c".repeat(40);
    assert_eq!(lab.add(&path, &digest, "cache", Some(&unknown)).code, 0);
    let status = lab.status();
    assert_eq!(file(&status, &path)["ref_ok"], false);
    assert_eq!(status["safe_to_clear"], false);
}

#[test]
fn origin_head_comes_before_main_then_master() {
    let lab = lab();
    let first = git(&lab.repo, &["rev-parse", "HEAD"]);
    git(&lab.repo, &["branch", "-q", "master"]);
    git(&lab.repo, &["switch", "-q", "master"]);
    let on_master = commit(&lab.repo, "m.txt");
    let (path, digest) = lab.write("a.py", "a");
    assert_eq!(lab.add(&path, &digest, "snapshot", Some(&on_master)).code, 0);

    // `main` is here and lacks the commit, so `master` is never asked.
    assert_eq!(lab.status()["safe_to_clear"], false);

    // Without `main`, `master` has it.
    git(&lab.repo, &["branch", "-q", "-D", "main"]);
    assert_eq!(lab.status()["safe_to_clear"], true);

    // `origin/HEAD` outranks both; here it points at the first commit, without the record's.
    git(&lab.repo, &["update-ref", "refs/remotes/origin/trunk", &first]);
    git(&lab.repo, &["symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/trunk"]);
    let status = lab.status();
    assert_eq!(status["safe_to_clear"], false);
    assert!(reasons(&status).contains("not an ancestor of origin/HEAD"), "{status}");
}

#[test]
fn no_default_branch_is_false_with_a_reason() {
    let lab = lab();
    let head = git(&lab.repo, &["rev-parse", "HEAD"]);
    git(&lab.repo, &["switch", "-q", "-c", "trunk"]);
    git(&lab.repo, &["branch", "-q", "-D", "main"]);
    let (path, digest) = lab.write("a.py", "a");
    assert_eq!(lab.add(&path, &digest, "cache", Some(&head)).code, 0);

    let status = lab.status();
    assert_eq!(file(&status, &path)["ref_ok"], false);
    assert_eq!(status["safe_to_clear"], false);
    assert!(reasons(&status).contains("no origin/HEAD, main or master"), "{status}");
}

#[test]
fn a_tag_named_main_is_not_the_default_branch() {
    let lab = lab();
    let head = git(&lab.repo, &["rev-parse", "HEAD"]);
    git(&lab.repo, &["tag", "main"]);
    git(&lab.repo, &["switch", "-q", "-c", "trunk"]);
    git(&lab.repo, &["branch", "-q", "-D", "main"]);
    let (path, digest) = lab.write("a.py", "a");
    assert_eq!(lab.add(&path, &digest, "cache", Some(&head)).code, 0);
    assert_eq!(lab.status()["safe_to_clear"], false);
}

#[test]
fn issues_discards_and_refusals_need_no_branch_and_refusals_are_named() {
    let lab = lab();
    git(&lab.repo, &["switch", "-q", "-c", "trunk"]);
    git(&lab.repo, &["branch", "-q", "-D", "main"]);
    let (a, a_sha) = lab.write("a.md", "a");
    let (b, b_sha) = lab.write("b.log", "b");
    let (c, c_sha) = lab.write("c.txt", "c");
    assert_eq!(lab.add(&a, &a_sha, "write-up", Some("issue:72")).code, 0);
    assert_eq!(lab.add(&b, &b_sha, "discard", None).code, 0);
    assert_eq!(lab.add(&c, &c_sha, "refuse", None).code, 0);

    let status = lab.status();
    assert_eq!(status["safe_to_clear"], true, "{}", reasons(&status));
    assert_eq!(file(&status, &a)["ref_ok"], true);
    assert_eq!(file(&status, &a)["ref"], "issue:72");
    assert_eq!(file(&status, &c)["ref"], Value::Null);
    assert_eq!(status["refused_deleted_on_clear"], serde_json::json!([c]));
}

#[test]
fn every_status_key_is_present_and_the_text_form_states_the_verdict() {
    let lab = lab();
    let (path, _) = lab.write("a.txt", "a");
    let status = lab.status();
    for key in ["files", "safe_to_clear", "reasons", "refused_deleted_on_clear", "skipped_lines"] {
        assert!(status.get(key).is_some(), "{key}");
    }
    for key in ["path", "sha256", "state", "handling", "ref", "ref_ok"] {
        assert!(file(&status, &path).get(key).is_some(), "{key}");
    }

    let run = lab.run(&["promotion", "status", TOPIC]);
    assert_eq!(run.code, 0);
    assert!(run.stdout.contains("safe_to_clear: false"), "{}", run.stdout);
    assert!(run.stdout.contains("reason: 1 file(s) have no record"), "{}", run.stdout);
    assert!(run.stdout.contains(&path), "{}", run.stdout);
}

#[test]
fn a_git_dir_in_the_environment_does_not_redirect_the_identity() {
    let lab = lab();
    let other = lab.repo.parent().unwrap().join("other");
    init(&other);
    commit(&other, "o.txt");
    let (path, sha) = lab.write("a.txt", "a");
    let out = Command::new(env!("CARGO_BIN_EXE_envscan"))
        .args(["promotion", "add", &path, "--sha256", &sha, "--handling", "discard"])
        .current_dir(&lab.repo)
        .env("HOME", &lab.home)
        .env("GIT_DIR", other.join(".git"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(file(&lab.status(), &path)["state"], "recorded");
}
