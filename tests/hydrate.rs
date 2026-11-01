//! `hydrate` and `dehydrate` as a caller sees them. The values are invented.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use tempfile::TempDir;

struct Run {
    code: i32,
    stdout: Vec<u8>,
    stderr: String,
}

impl Run {
    fn out(&self) -> String {
        String::from_utf8(self.stdout.clone()).unwrap()
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
    // A command that exits before reading closes the pipe, which is its own business.
    let _ = child.stdin.take().unwrap().write_all(stdin);
    let out = child.wait_with_output().unwrap();
    Run {
        code: out.status.code().expect("exited, not signalled"),
        stdout: out.stdout,
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

fn hydrate(cwd: &Path, stdin: &str) -> Run {
    run_with_stdin(cwd, &["hydrate", "--stdin", "--env", ".env"], stdin.as_bytes())
}

fn dehydrate(cwd: &Path, stdin: &[u8]) -> Run {
    run_with_stdin(cwd, &["dehydrate", "--stdin", "--env", ".env"], stdin)
}

fn dir_with(env: &str, example: Option<&str>) -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join(".env"), env).unwrap();
    if let Some(example) = example {
        fs::write(dir.path().join(".env.example"), example).unwrap();
    }
    dir
}

fn fixture_dir() -> TempDir {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/roundtrip");
    let dir = TempDir::new().unwrap();
    fs::copy(root.join("env"), dir.path().join(".env")).unwrap();
    fs::copy(root.join("env.example"), dir.path().join(".env.example")).unwrap();
    fs::copy(root.join("parameterized.md"), dir.path().join("parameterized.md")).unwrap();
    dir
}

/// Hydrate then dehydrate returns the input, apart from `${KEY}` written where `$KEY` would do,
/// which the caller folds into `want`.
fn assert_round_trip(dir: &Path, input: &[u8], want: &[u8]) {
    let wet = run_with_stdin(dir, &["hydrate", "--stdin", "--env", ".env"], input);
    assert_eq!(wet.code, 0, "{}", wet.stderr);
    let dry = dehydrate(dir, &wet.stdout);
    assert_eq!(dry.code, 0, "{}", dry.stderr);
    assert_eq!(String::from_utf8_lossy(&dry.stdout), String::from_utf8_lossy(want));
}

#[test]
fn the_fixture_round_trips_exactly() {
    let dir = fixture_dir();
    let input = fs::read(dir.path().join("parameterized.md")).unwrap();
    assert_round_trip(dir.path(), &input, &input);
}

#[test]
fn a_path_hydrates_with_an_env_and_exits_2_with_no_key_list() {
    let dir = fixture_dir();
    let run = run_with_stdin(dir.path(), &["hydrate", "parameterized.md"], b"");
    // The fixture dir is no git repo, so this also pins that a path alone finds no env.
    assert_eq!(run.code, 2, "{}", run.stderr);

    let run = run_with_stdin(dir.path(), &["hydrate", "parameterized.md", "--env", ".env"], b"");
    assert_eq!(run.code, 0, "{}", run.stderr);
    let out = run.out();
    assert!(out.contains("tmp/extracted/zqxbeta_warehouse"));
    assert!(out.contains("https://hooks.zqxgamma.example/in"));
    assert!(out.contains("/srv/zqxdelta/data"));
    assert!(out.contains("Left alone: $HOME, ${HOME}, $1, $$, $VAR, $(date), ${ZQ_CLIENT:-x}, $ZQ_UNLISTED,"));
    assert!(!out.contains("$ZQ_REPO"));
}

#[test]
fn braces_that_were_not_needed_come_back_bare() {
    let dir = fixture_dir();
    assert_round_trip(dir.path(), b"${ZQ_CLIENT} ${ZQ_CLIENT}.md", b"$ZQ_CLIENT $ZQ_CLIENT.md");
}

#[test]
fn bytes_that_are_not_utf8_round_trip() {
    let dir = fixture_dir();
    let input = b"\xff$ZQ_CLIENT\xfe \xe2\x82";
    assert_round_trip(dir.path(), input, input);
}

/// The stated cost of "whole words only": a key touching a word character fills to a longer
/// word, which dehydrate leaves alone, as the scanner does. This is the one way the round trip
/// does not hold, so write such a name as its own key.
#[test]
fn a_key_touching_a_word_character_does_not_come_back() {
    let dir = dir_with("KEY=zqxvalue\n", None);
    for (input, wet) in [
        ("${KEY}_raw", "zqxvalue_raw"),
        ("${KEY}s", "zqxvalues"),
        ("pre$KEY", "prezqxvalue"),
        ("$KEY$KEY", "zqxvaluezqxvalue"),
    ] {
        let run = hydrate(dir.path(), input);
        assert_eq!(run.out(), wet);
        assert_eq!(dehydrate(dir.path(), wet.as_bytes()).out(), wet);
    }
}

#[test]
fn two_keys_with_one_value_come_back_as_the_first() {
    let dir = dir_with("A=zqxvalue\nB=zqxvalue\n", None);
    assert_eq!(dehydrate(dir.path(), hydrate(dir.path(), "$B").stdout.as_slice()).out(), "$A");
}

#[test]
fn a_listed_key_with_no_value_exits_2_names_it_and_prints_no_text() {
    let dir = dir_with("FILLED=zqxvalue\nEMPTY=\n", Some("ONLY_EXAMPLE=\n"));
    for (input, named) in [("$FILLED $EMPTY", "EMPTY"), ("${ONLY_EXAMPLE}", "ONLY_EXAMPLE")] {
        let run = hydrate(dir.path(), input);
        assert_eq!(run.code, 2);
        assert!(run.stderr.contains(named), "{}", run.stderr);
        assert!(!run.stderr.contains("zqxvalue"));
        assert!(run.stdout.is_empty());
    }
}

#[test]
fn a_listed_key_the_text_does_not_name_is_no_failure() {
    let dir = dir_with("FILLED=zqxvalue\nEMPTY=\n", Some("ONLY_EXAMPLE=\n"));
    assert_eq!(hydrate(dir.path(), "$FILLED").out(), "zqxvalue");
}

#[test]
fn home_and_other_unlisted_names_pass_through() {
    let dir = dir_with("KEY=zqxvalue\n", Some("KEY=\n"));
    let text = "$HOME ${HOME} $1 $UNLISTED ${UNLISTED}\n";
    let run = hydrate(dir.path(), text);
    assert_eq!((run.code, run.out().as_str()), (0, text));
}

#[test]
fn a_value_in_the_example_file_is_never_filled() {
    let dir = dir_with("OTHER=zqxvalue\n", Some("KEY=zqxexample\n"));
    let run = hydrate(dir.path(), "$KEY");
    assert_eq!(run.code, 2);
    assert!(run.stdout.is_empty());
}

#[test]
fn check_prints_key_names_and_no_value() {
    let dir = dir_with("KEY=zqxvalue\nEMPTY=\n", None);
    let check = |text: &str| {
        run_with_stdin(dir.path(), &["hydrate", "--stdin", "--env", ".env", "--check"], text.as_bytes())
    };
    let good = check("$KEY $HOME");
    assert_eq!(good.code, 0);
    assert_eq!(good.out(), "keys used: KEY\nall keys resolve\n");
    let bad = check("$KEY $EMPTY");
    assert_eq!(bad.code, 2);
    assert_eq!(bad.out(), "keys used: KEY EMPTY\n");
    assert!(bad.stderr.contains("EMPTY"));
    assert!(!format!("{}{}", bad.out(), bad.stderr).contains("zqxvalue"));
}

#[test]
fn a_fresh_clone_with_only_the_example_exits_2_naming_keys() {
    let dir = TempDir::new().unwrap();
    let status = Command::new("git")
        .args(["init", "-q"])
        .current_dir(dir.path())
        .status()
        .unwrap();
    assert!(status.success());
    fs::write(dir.path().join(".env.example"), "KEY=\n").unwrap();
    fs::create_dir(dir.path().join("sub")).unwrap();
    let run = run_with_stdin(&dir.path().join("sub"), &["hydrate", "--stdin"], b"read $KEY");
    assert_eq!(run.code, 2);
    assert!(run.stderr.contains("KEY"), "{}", run.stderr);
    assert!(run.stderr.contains(".env.example"), "{}", run.stderr);

    let run = run_with_stdin(&dir.path().join("sub"), &["hydrate", "--stdin"], b"read $HOME");
    assert_eq!((run.code, run.out().as_str()), (0, "read $HOME"));
}

#[test]
fn discovery_finds_the_env_at_the_repo_root() {
    let dir = TempDir::new().unwrap();
    let status = Command::new("git")
        .args(["init", "-q"])
        .current_dir(dir.path())
        .status()
        .unwrap();
    assert!(status.success());
    fs::write(dir.path().join(".env"), "KEY=zqxvalue\n").unwrap();
    fs::create_dir(dir.path().join("sub")).unwrap();
    fs::write(dir.path().join("sub/t.md"), "$KEY").unwrap();
    let run = run_with_stdin(&dir.path().join("sub"), &["hydrate", "t.md"], b"");
    assert_eq!((run.code, run.out().as_str()), (0, "zqxvalue"));
    let run = run_with_stdin(&dir.path().join("sub"), &["dehydrate", "--stdin"], b"zqxvalue");
    assert_eq!((run.code, run.out().as_str()), (0, "$KEY"));
}

#[test]
fn outside_any_key_list_both_refuse_rather_than_look_done() {
    let dir = TempDir::new().unwrap();
    let wet = run_with_stdin(dir.path(), &["hydrate", "--stdin"], b"$KEY");
    assert_eq!(wet.code, 2);
    assert!(wet.stdout.is_empty());
    let dry = run_with_stdin(dir.path(), &["dehydrate", "--stdin"], b"zqxvalue");
    assert_eq!(dry.code, 2);
    assert!(dry.stdout.is_empty());
}

#[test]
fn dehydrate_with_no_usable_value_refuses() {
    let dir = dir_with("EMPTY=\nSHORT=ab\n", None);
    let run = dehydrate(dir.path(), b"text");
    assert_eq!(run.code, 2);
    assert!(run.stdout.is_empty());
}

#[test]
fn dehydrate_names_a_value_too_short_to_replace() {
    let dir = dir_with("SHORT=ab\nKEY=zqxvalue\n", None);
    let run = dehydrate(dir.path(), b"ab zqxvalue");
    assert_eq!((run.code, run.out().as_str()), (0, "ab $KEY"));
    assert!(run.stderr.contains("SHORT"), "{}", run.stderr);
    assert!(!run.stderr.contains("zqxvalue"));
}

#[test]
fn usage_and_io_errors_exit_3() {
    let dir = dir_with("KEY=zqxvalue\n", None);
    for (args, stdin) in [
        (vec!["hydrate", "--env", ".env"], &b""[..]),
        (vec!["hydrate", "a.md", "--stdin", "--env", ".env"], b""),
        (vec!["hydrate", "missing.md", "--env", ".env"], b""),
        (vec!["hydrate", "--stdin", "--env", "missing.env"], b"$KEY"),
        (vec!["dehydrate", "--env", ".env"], b""),
        (vec!["dehydrate", "a.md", "--stdin", "--env", ".env"], b""),
        (vec!["dehydrate", "missing.md", "--env", ".env"], b""),
        (vec!["dehydrate", "--stdin", "--env", "missing.env"], b"zqxvalue"),
    ] {
        let run = run_with_stdin(dir.path(), &args, stdin);
        assert_eq!(run.code, 3, "{args:?}: {}", run.stderr);
        assert!(run.stdout.is_empty(), "{args:?}");
    }
}

#[test]
fn a_missing_path_holding_a_value_is_shown_by_key() {
    let dir = dir_with("KEY=zqxvalue\n", None);
    let run = run_with_stdin(dir.path(), &["hydrate", "zqxvalue/a.md", "--env", ".env"], b"");
    assert_eq!(run.code, 3);
    assert!(run.stderr.contains("$KEY/a.md"), "{}", run.stderr);
    assert!(!run.stderr.contains("zqxvalue"));
}

#[test]
fn neither_command_writes_the_input_file() {
    let dir = dir_with("KEY=zqxvalue\n", None);
    fs::write(dir.path().join("t.md"), "$KEY zqxvalue").unwrap();
    for command in ["hydrate", "dehydrate"] {
        assert_eq!(run_with_stdin(dir.path(), &[command, "t.md", "--env", ".env"], b"").code, 0);
        assert_eq!(fs::read_to_string(dir.path().join("t.md")).unwrap(), "$KEY zqxvalue");
    }
}

/// The fixture's real text is dehydrated by exact written form, and that dehydrated form is what
/// has to survive. It holds `$SRC_DIR`, `$LOG_DIR` and `$1`-style names that must pass through.
#[test]
fn the_broad_fixture_round_trips() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/broad/fixture");
    let dir = dir_with(
        "ZQ_A=Veldquiver Analytics\nZQ_B=veldquiver/etl-core\nZQ_C=quill-dwh-prod-4821\nZQ_D=gs://acme-raw-bucket\n\
         ZQ_E=10.20.30.41\nZQ_F=db1.internal\nZQ_G=dmorlask\nZQ_H=Brambleway Foods\nZQ_I=483920117462\n",
        None,
    );
    let mut replaced = 0;
    for rel in ["config/pipeline.json", "logs/run-1182.log", "notes/handoff-bramble.md",
        "notes/scratch-ideas.md", "notes/session-2026-10-30.md", "scripts/check_hosts.py", "scripts/sync_raw.sh"] {
        let text = fs::read(root.join(rel)).unwrap();
        let dry = dehydrate(dir.path(), &text);
        assert_eq!(dry.code, 0, "{}", dry.stderr);
        assert_ne!(dry.stdout, text, "{rel} should hold a planted value");
        replaced += 1;
        assert_round_trip(dir.path(), &dry.stdout, &dry.stdout);
        let wet = hydrate(dir.path(), &dry.out());
        assert_eq!(wet.stdout, text, "{rel}: the fixture's values are written in one case each");
    }
    assert_eq!(replaced, 7);
}
