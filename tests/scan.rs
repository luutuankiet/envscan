//! The binary as a caller sees it: exit codes, JSON shape, discovery, walk scope.
//! Trees are built in temp dirs; the values are invented.

use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use tempfile::TempDir;

const VALUE: &str = "zqxvalue";

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).expect("stdout is JSON")
    }
    fn hits(&self, key: &str) -> (u64, u64) {
        let json = self.json();
        let leak = json["leaks"].as_array().unwrap().iter().find(|l| l["key"] == key);
        leak.map_or((0, 0), |l| (l["strict"].as_u64().unwrap(), l["loose"].as_u64().unwrap()))
    }
}

fn run_with_stdin(cwd: &Path, args: &[&str], stdin: &[u8]) -> Run {
    let mut child = Command::new(env!("CARGO_BIN_EXE_envscan"))
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let out = child.wait_with_output().unwrap();
    Run {
        code: out.status.code().expect("exited, not signalled"),
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

fn run(cwd: &Path, args: &[&str]) -> Run {
    run_with_stdin(cwd, args, b"")
}

fn write(root: &Path, rel: &str, text: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn git(cwd: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(["-c", "user.name=t", "-c", "user.email=t"])
        .args(args)
        .current_dir(cwd)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

/// A temp tree with a rules file outside the scanned folder.
fn tree() -> (TempDir, String) {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "rules/vals", &format!("KEY_A={VALUE}\n"));
    let env = dir.path().join("rules/vals").display().to_string();
    fs::create_dir(dir.path().join("t")).unwrap();
    (dir, env)
}

#[test]
fn exit_0_on_a_clean_tree_and_1_on_strict_or_loose() {
    let (dir, env) = tree();
    let t = dir.path().join("t");
    write(&t, "a.md", "nothing here\n");
    assert_eq!(run(&t, &["scan", ".", "--env", &env]).code, 0);

    write(&t, "b.md", &format!("line\n{VALUE}\n"));
    let r = run(&t, &["scan", ".", "--env", &env, "--json"]);
    assert_eq!(r.code, 1);
    assert_eq!(r.hits("KEY_A"), (1, 0));
    assert_eq!(r.json()["leaks"][0]["at"][0], "b.md:2");

    write(&t, "b.md", &format!("gs://{VALUE}-raw\n"));
    let r = run(&t, &["scan", ".", "--env", &env, "--json"]);
    assert_eq!(r.code, 1, "a loose-only hit still exits 1");
    assert_eq!(r.hits("KEY_A"), (0, 1));
}

#[test]
fn exit_2_when_no_rules_load_and_never_clean() {
    let (dir, _) = tree();
    let t = dir.path().join("t");
    write(&t, "a.md", "text\n");
    write(dir.path(), "empty", "");
    write(dir.path(), "short", "S=ab\nE=\n");
    for name in ["empty", "short"] {
        let env = dir.path().join(name).display().to_string();
        let r = run(&t, &["scan", ".", "--env", &env, "--json"]);
        assert_eq!(r.code, 2, "{name}");
        assert_eq!(r.json()["rules_loaded"], 0);
    }
    // No --env, and no repo at all.
    assert_eq!(run(&t, &["scan", "."]).code, 2);
}

#[test]
fn exit_3_for_usage_missing_path_bad_env_and_nothing_scanned() {
    let (dir, env) = tree();
    let t = dir.path().join("t");
    write(&t, "a.md", "text\n");
    for args in [
        vec!["scan", "--bogus"],
        vec!["scan", "--env"],
        vec!["scan", "--top", "abc"],
        vec!["nonsense"],
        vec![],
    ] {
        assert_eq!(run(&t, &args).code, 3, "{args:?}");
    }
    // A missing path wins even beside a real leak.
    write(&t, "leak.md", VALUE);
    assert_eq!(run(&t, &["scan", "leak.md", "gone", "--env", &env]).code, 3);
    assert_eq!(run(&t, &["scan", "gone", "--env", &env]).code, 3);
    assert_eq!(run(&t, &["scan", "a.md", "--env", "no-such-env"]).code, 3);

    let empty = dir.path().join("empty");
    fs::create_dir(&empty).unwrap();
    let r = run(&empty, &["scan", ".", "--env", &env]);
    assert_eq!(r.code, 3);
    assert!(r.stderr.contains("nothing scanned"));
}

#[test]
fn help_and_version_exit_0() {
    let dir = TempDir::new().unwrap();
    assert_eq!(run(dir.path(), &["--help"]).code, 0);
    assert_eq!(run(dir.path(), &["--version"]).code, 0);
}

#[test]
fn json_has_every_key_in_a_stable_shape() {
    let (dir, env) = tree();
    let t = dir.path().join("t");
    write(&t, "a.md", "text\n");
    let json = run(&t, &["scan", ".", "--env", &env, "--json"]).json();
    let mut keys: Vec<&String> = json.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        ["candidates", "candidates_by_kind", "candidates_total", "data_files",
         "env_unparsed_lines", "extractor_errors", "files_scanned", "leaks", "rules_loaded",
         "short_values", "skipped", "tier"]
    );
    let mut skipped: Vec<&String> = json["skipped"].as_object().unwrap().keys().collect();
    skipped.sort();
    assert_eq!(skipped, ["binary", "large", "long_lines", "non_utf8", "secret_named"]);
    assert_eq!(json["tier"], "plain");
    assert_eq!(json["candidates"], serde_json::json!([]));
    assert_eq!(json["data_files"], serde_json::json!([]));
    assert_eq!(json["candidates_total"], 0);
    assert_eq!(json["candidates_by_kind"], serde_json::json!({}));
}

#[test]
fn env_problems_are_reported_by_number_and_key() {
    let dir = TempDir::new().unwrap();
    let t = dir.path().join("t");
    write(&t, "a.md", &format!("{VALUE}\n"));
    write(
        dir.path(),
        "vals",
        &format!("\u{feff}FIRST = {VALUE}\nSECRETLINE no equals\nDUP={VALUE}\nS=ab\nE=\n"),
    );
    let env = dir.path().join("vals").display().to_string();
    let r = run(&t, &["scan", ".", "--env", &env, "--json"]);
    assert_eq!(r.code, 1);
    let json = r.json();
    assert_eq!(json["env_unparsed_lines"], serde_json::json!([2]));
    assert_eq!(json["short_values"], serde_json::json!(["S"]));
    assert_eq!(json["rules_loaded"], 1);
    assert_eq!(r.hits("FIRST"), (1, 0));
    assert_eq!(r.hits("DUP"), (1, 0));
    assert!(!r.stdout.contains("SECRETLINE"));
}

#[test]
fn short_values_do_not_match() {
    let dir = TempDir::new().unwrap();
    let t = dir.path().join("t");
    write(&t, "a.md", "ab\n");
    write(dir.path(), "vals", &format!("S=ab\nKEY_A={VALUE}\n"));
    let env = dir.path().join("vals").display().to_string();
    assert_eq!(run(&t, &["scan", ".", "--env", &env]).code, 0);
}

#[test]
fn the_report_never_holds_a_value_outside_full() {
    let (dir, env) = tree();
    let t = dir.path().join("t");
    write(&t, &format!("{VALUE}-dir/{VALUE}.md"), &format!("x {VALUE} y\n"));
    for extra in [vec!["--json"], vec![]] {
        let mut args = vec!["scan", ".", "--env", &env];
        args.extend(extra);
        let r = run(&t, &args);
        assert_eq!(r.code, 1);
        assert!(!r.stdout.contains(VALUE), "{}", r.stdout);
        assert!(r.stdout.contains("$KEY_A"));
    }
    let r = run(&t, &["scan", ".", "--env", &env, "--full"]);
    assert!(r.stdout.contains(VALUE), "--full shows the real path");
}

#[test]
fn file_and_directory_names_are_matched() {
    let (dir, env) = tree();
    let t = dir.path().join("t");
    write(&t, &format!("{VALUE}.md"), "clean text\n");
    let r = run(&t, &["scan", ".", "--env", &env, "--json"]);
    assert_eq!(r.code, 1);
    assert_eq!(r.hits("KEY_A"), (1, 0));

    fs::remove_file(t.join(format!("{VALUE}.md"))).unwrap();
    write(&t, &format!("a-{VALUE}/x.md"), "clean text\n");
    let r = run(&t, &["scan", ".", "--env", &env, "--json"]);
    assert_eq!(r.code, 1);
    assert_eq!(r.hits("KEY_A"), (0, 1));
}

#[test]
fn a_name_hit_counts_even_when_the_file_cannot_be_scanned() {
    let (dir, env) = tree();
    let t = dir.path().join("t");
    fs::write(t.join(format!("{VALUE}.bin")), b"\0\0\0").unwrap();
    let r = run(&t, &["scan", ".", "--env", &env, "--json"]);
    assert_eq!(r.code, 1);
    assert_eq!(r.json()["skipped"]["binary"], 1);
}

#[test]
fn a_root_directory_name_is_the_callers_not_a_hit() {
    let (dir, env) = tree();
    let root = dir.path().join(VALUE);
    write(&root, "a.md", "clean\n");
    assert_eq!(run(dir.path(), &["scan", VALUE, "--env", &env]).code, 0);
}

#[test]
fn env_and_secret_named_files_are_always_excluded() {
    let (dir, env) = tree();
    let t = dir.path().join("t");
    for name in [".env", ".env.local", "a.pem", "b.key", "id_rsa", "client_secret.json"] {
        write(&t, name, &format!("{VALUE}\n"));
    }
    write(&t, "clean.md", "clean\n");
    for extra in [vec![], vec!["--no-ignore"]] {
        let mut args = vec!["scan", ".", "--env", &env, "--json"];
        args.extend(extra);
        let r = run(&t, &args);
        assert_eq!(r.code, 0, "{}", r.stdout);
        assert_eq!(r.json()["skipped"]["secret_named"], 6);
        assert_eq!(r.json()["files_scanned"], 1);
    }
    // Named directly, it is still excluded, and that leaves nothing scanned.
    assert_eq!(run(&t, &["scan", ".env", "--env", &env]).code, 3);
}

#[test]
fn the_rules_file_is_excluded_whatever_it_is_called() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "vals.txt", &format!("KEY_A={VALUE}\n"));
    write(dir.path(), "a.md", "clean\n");
    let r = run(dir.path(), &["scan", ".", "--env", "vals.txt", "--json"]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(r.json()["skipped"]["secret_named"], 1);
}

#[test]
fn an_example_env_with_a_real_value_is_a_leak() {
    let (dir, env) = tree();
    let t = dir.path().join("t");
    write(&t, ".env.example", &format!("KEY_A={VALUE}\n"));
    assert_eq!(run(&t, &["scan", ".", "--env", &env]).code, 1);
}

#[test]
fn skip_counts() {
    let (dir, env) = tree();
    let t = dir.path().join("t");
    write(&t, "ok.md", "ok\n");
    fs::write(t.join("bin.dat"), b"a\0b").unwrap();
    fs::write(t.join("latin.txt"), b"caf\xe9\n").unwrap();
    fs::write(t.join("big.txt"), vec![b'a'; 2_000_001]).unwrap();
    let json = run(&t, &["scan", ".", "--env", &env, "--json"]).json();
    assert_eq!(json["files_scanned"], 1);
    assert_eq!(json["skipped"]["binary"], 1);
    assert_eq!(json["skipped"]["non_utf8"], 1);
    assert_eq!(json["skipped"]["large"], 1);
}

#[test]
fn stdin_is_scanned() {
    let (dir, env) = tree();
    let t = dir.path().join("t");
    let r = run_with_stdin(&t, &["scan", "--stdin", "--env", &env, "--json"], format!("a\n{VALUE}\n").as_bytes());
    assert_eq!(r.code, 1);
    assert_eq!(r.json()["leaks"][0]["at"][0], "<stdin>:2");
    assert_eq!(run_with_stdin(&t, &["scan", "--stdin", "--env", &env], b"clean\n").code, 0);
    // Stdin that cannot be scanned is not clean.
    assert_eq!(run_with_stdin(&t, &["scan", "--stdin", "--env", &env], b"a\0b").code, 3);
}

#[test]
fn stdin_and_paths_are_scanned_together() {
    let (dir, env) = tree();
    let t = dir.path().join("t");
    write(&t, "a.md", &format!("{VALUE}\n"));
    let r = run_with_stdin(&t, &["scan", "a.md", "--stdin", "--env", &env, "--json"], format!("{VALUE}\n").as_bytes());
    assert_eq!(r.hits("KEY_A"), (2, 0));
    assert_eq!(r.json()["files_scanned"], 2);
}

#[test]
fn overlapping_roots_count_a_file_once() {
    let (dir, env) = tree();
    let t = dir.path().join("t");
    write(&t, "sub/a.md", &format!("{VALUE}\n"));
    let r = run(&t, &["scan", ".", "sub", "sub/a.md", "--env", &env, "--json"]);
    assert_eq!(r.json()["files_scanned"], 1);
    assert_eq!(r.hits("KEY_A"), (1, 0));
}

#[test]
fn full_lists_every_location_and_default_caps_them() {
    let (dir, env) = tree();
    let t = dir.path().join("t");
    for i in 0..5 {
        write(&t, &format!("f{i}.md"), &format!("{VALUE}\n"));
    }
    let capped = run(&t, &["scan", ".", "--env", &env, "--json"]).json();
    assert_eq!(capped["leaks"][0]["at"].as_array().unwrap().len(), 3);
    assert_eq!(capped["leaks"][0]["strict"], 5);
    let full = run(&t, &["scan", ".", "--env", &env, "--json", "--full"]).json();
    assert_eq!(full["leaks"][0]["at"].as_array().unwrap().len(), 5);
}

// ---- discovery

#[test]
fn discovery_finds_the_repo_root_env_from_a_subdirectory() {
    let dir = TempDir::new().unwrap();
    git(dir.path(), &["init", "-q"]);
    write(dir.path(), ".env", &format!("KEY_A={VALUE}\n"));
    write(dir.path(), "deep/er/a.md", &format!("{VALUE}\n"));
    let r = run(&dir.path().join("deep/er"), &["scan", ".", "--json"]);
    assert_eq!(r.code, 1);
    assert_eq!(r.hits("KEY_A"), (1, 0));
}

#[test]
fn discovery_from_a_linked_worktree_reaches_the_main_checkouts_env() {
    let dir = TempDir::new().unwrap();
    let main = dir.path().join("main");
    fs::create_dir(&main).unwrap();
    git(&main, &["init", "-q"]);
    write(&main, ".gitignore", ".env\n");
    git(&main, &["add", ".gitignore"]);
    git(&main, &["commit", "-qm", "init"]);
    write(&main, ".env", &format!("KEY_A={VALUE}\n"));
    git(&main, &["worktree", "add", "-q", "../wt"]);
    let wt = dir.path().join("wt");
    assert!(!wt.join(".env").exists());
    write(&wt, "a.md", &format!("{VALUE}\n"));
    let r = run(&wt, &["scan", ".", "--json"]);
    assert_eq!(r.code, 1, "a worktree without a .env must not fail open");
    assert_eq!(r.hits("KEY_A"), (1, 0));
    assert_eq!(r.json()["files_scanned"], 2, "the .git pointer file is not scanned");
}

#[test]
fn explicit_env_beats_discovery() {
    let dir = TempDir::new().unwrap();
    git(dir.path(), &["init", "-q"]);
    write(dir.path(), ".env", "KEY_REPO=zqxother\n");
    write(dir.path(), "vals", &format!("KEY_A={VALUE}\n"));
    write(dir.path(), "a.md", &format!("{VALUE} zqxother\n"));
    let r = run(dir.path(), &["scan", "a.md", "--env", "vals", "--json"]);
    assert_eq!(r.hits("KEY_A"), (1, 0));
    assert_eq!(r.hits("KEY_REPO"), (0, 0));
}

// ---- walk scope

/// An outer repo that ignores `tmp/` and `*.secretlog`, holding a real nested repo with its
/// own ignore file.
fn nested_repo() -> TempDir {
    let dir = TempDir::new().unwrap();
    let outer = dir.path();
    git(outer, &["init", "-q"]);
    write(outer, ".gitignore", "tmp/\n*.secretlog\n");
    write(outer, "tmp/topic/a.md", &format!("{VALUE}\n"));
    write(outer, "tmp/topic/.gitignore", "drop.md\n");
    write(outer, "tmp/topic/drop.md", &format!("{VALUE}\n"));
    write(outer, "plain.md", "clean\n");
    let inner = outer.join("nested");
    fs::create_dir(&inner).unwrap();
    git(&inner, &["init", "-q"]);
    write(&inner, ".gitignore", "own.log\n");
    write(&inner, "own.log", "zqxinnerown\n");
    write(&inner, "hidden.secretlog", "zqxinnerouter\n");
    write(&inner, "seen.md", "clean\n");
    write(outer, "vals", &format!("KEY_A={VALUE}\nKEY_OWN=zqxinnerown\nKEY_OUTER=zqxinnerouter\n"));
    dir
}

#[test]
fn scanning_a_repo_root_prunes_the_tmp_it_ignores() {
    let dir = nested_repo();
    let r = run(dir.path(), &["scan", ".", "--env", "vals", "--json"]);
    assert_eq!(r.hits("KEY_A"), (0, 0));
}

#[test]
fn naming_the_topic_folder_as_the_root_scans_it_and_keeps_its_own_rules() {
    let dir = nested_repo();
    let r = run(dir.path(), &["scan", "tmp/topic", "--env", "vals", "--json"]);
    assert_eq!(r.code, 1);
    assert_eq!(r.hits("KEY_A"), (1, 0), "a.md hits and drop.md is ignored by its folder's rule");
}

#[test]
fn a_named_ignored_file_is_scanned() {
    let dir = nested_repo();
    let r = run(dir.path(), &["scan", "tmp/topic/drop.md", "--env", "vals"]);
    assert_eq!(r.code, 1);
}

#[test]
fn no_ignore_sees_every_rule_hidden_file() {
    let dir = nested_repo();
    let r = run(dir.path(), &["scan", ".", "--env", "vals", "--json", "--no-ignore"]);
    assert_eq!(r.hits("KEY_A"), (2, 0));
    assert_eq!(r.hits("KEY_OWN"), (1, 0));
    assert_eq!(r.hits("KEY_OUTER"), (1, 0));
}

#[test]
fn a_nested_repo_honours_its_own_ignore_rules() {
    let dir = nested_repo();
    let r = run(dir.path(), &["scan", "nested", "--env", "vals", "--json"]);
    assert_eq!(r.hits("KEY_OWN"), (0, 0));
    assert_eq!(r.hits("KEY_OUTER"), (1, 0), "from inside, the outer rule does not apply");
}

/// The accepted gap, pinned on a real nested repo: an outer rule hides a file that the nested
/// repo's own git would not ignore. If this starts failing the gap has closed; update the
/// comment at the top of the walker.
#[test]
fn accepted_gap_an_outer_rule_hides_a_file_in_a_nested_repo() {
    let dir = nested_repo();
    let inner = dir.path().join("nested");
    let tracked_by_inner = Command::new("git")
        .args(["check-ignore", "-q", "hidden.secretlog"])
        .current_dir(&inner)
        .status()
        .unwrap();
    assert_eq!(tracked_by_inner.code(), Some(1), "the nested repo's own git does not ignore it");
    let r = run(dir.path(), &["scan", ".", "--env", "vals", "--json"]);
    assert_eq!(r.hits("KEY_OUTER"), (0, 0));
}

#[test]
fn generated_directories_are_pruned_unless_no_ignore_but_authored_names_are_not() {
    let (dir, env) = tree();
    let t = dir.path().join("t");
    write(&t, "node_modules/x/a.js", &format!("{VALUE}\n"));
    write(&t, "ok.md", "clean\n");
    assert_eq!(run(&t, &["scan", ".", "--env", &env]).code, 0);
    assert_eq!(run(&t, &["scan", ".", "--env", &env, "--no-ignore"]).code, 1);
    write(&t, "build/report.md", &format!("{VALUE}\n"));
    assert_eq!(run(&t, &["scan", ".", "--env", &env]).code, 1);
}

#[test]
fn git_internals_are_never_scanned() {
    let dir = TempDir::new().unwrap();
    git(dir.path(), &["init", "-q"]);
    write(dir.path(), ".git/description", &format!("{VALUE}\n"));
    write(dir.path(), "vals", &format!("KEY_A={VALUE}\n"));
    write(dir.path(), "a.md", "clean\n");
    assert_eq!(run(dir.path(), &["scan", ".", "--env", "vals", "--no-ignore"]).code, 0);
}

#[test]
fn a_symlink_root_is_followed_and_inner_symlinks_are_not() {
    let (dir, env) = tree();
    let t = dir.path().join("t");
    write(&t, "real/a.md", &format!("{VALUE}\n"));
    std::os::unix::fs::symlink(t.join("real"), t.join("link")).unwrap();
    assert_eq!(run(&t, &["scan", "link", "--env", &env]).code, 1);
    let r = run(&t, &["scan", ".", "--env", &env, "--json"]);
    assert_eq!(r.hits("KEY_A"), (1, 0), "real/a.md only, not again through link");
}

#[test]
fn a_broken_symlink_named_as_a_root_is_a_missing_path() {
    let (dir, env) = tree();
    let t = dir.path().join("t");
    std::os::unix::fs::symlink("nowhere", t.join("dead")).unwrap();
    assert_eq!(run(&t, &["scan", "dead", "--env", &env]).code, 3);
}

#[test]
fn an_unreadable_file_is_not_clean() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, env) = tree();
    let t = dir.path().join("t");
    write(&t, "ok.md", "clean\n");
    write(&t, "locked.md", "text\n");
    fs::set_permissions(t.join("locked.md"), fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read(t.join("locked.md")).is_ok() {
        return; // Running as root, permissions do not apply.
    }
    let r = run(&t, &["scan", ".", "--env", &env]);
    assert_eq!(r.code, 3);
    assert!(r.stderr.contains("locked.md"));
}

#[test]
fn a_closed_stdout_is_not_clean() {
    let (dir, env) = tree();
    let t = dir.path().join("t");
    write(&t, "ok.md", "clean\n");
    let mut child = Command::new(env!("CARGO_BIN_EXE_envscan"))
        .args(["scan", ".", "--env", &env])
        .current_dir(&t)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    assert_ne!(child.wait().unwrap().code(), Some(0));
}
