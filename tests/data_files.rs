//! Data files and the report's text form, through the binary. The values are invented.

use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

const VALUE: &str = "zqxvalue";
const UNSCANNED: &[&str] =
    &["xlsx", "xls", "parquet", "sqlite", "db", "avro", "orc", "hyper", "twbx", "tdsx"];

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn scan(dir: &TempDir, args: &[&str]) -> Run {
    let env = dir.path().join("rules/vals").display().to_string();
    let out = Command::new(env!("CARGO_BIN_EXE_envscan"))
        // No saved tier: an operator's `live` must never send fixture lines.
        .env("HOME", "/nonexistent-envscan-test-home")
        .args(["scan", "--env", &env])
        .args(args)
        .current_dir(dir.path())
        .output()
        .unwrap();
    Run {
        code: out.status.code().unwrap(),
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

fn json(run: &Run) -> Value {
    serde_json::from_str(&run.stdout).unwrap()
}

fn tree(files: &[(&str, &[u8])]) -> TempDir {
    let dir = TempDir::new().unwrap();
    let mut all: Vec<(&str, Vec<u8>)> = vec![("rules/vals", format!("KEY_A={VALUE}\n").into_bytes())];
    all.extend(files.iter().map(|(p, b)| (*p, b.to_vec())));
    for (rel, bytes) in all {
        let path = dir.path().join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fs::create_dir_all(dir.path().join("t")).unwrap();
    dir
}

fn entry<'a>(report: &'a Value, path: &str) -> &'a Value {
    report["data_files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["path"] == path)
        .unwrap_or_else(|| panic!("{path} not listed: {report}"))
}

#[test]
fn a_text_form_is_matched_past_the_size_cap_with_no_extractor() {
    let mut big = b"id,note\n".to_vec();
    big.resize(3_000_000, b'x');
    big.extend_from_slice(format!("\n1,{VALUE}\n2,qhost.internal\n").as_bytes());
    let dir = tree(&[("t/big.csv", &big)]);
    let run = scan(&dir, &["t", "--json"]);
    let report = json(&run);
    assert_eq!(run.code, 1, "{}", run.stderr);
    assert_eq!(report["leaks"][0]["key"], "KEY_A");
    assert_eq!(report["leaks"][0]["at"][0], "t/big.csv:3");
    assert_eq!(report["files_scanned"], 1);
    assert_eq!(report["skipped"]["large"], 0);
    assert_eq!(report["candidates_total"], 0);
    let listed = entry(&report, "t/big.csv");
    assert_eq!(listed["format"], "csv");
    assert_eq!(listed["scanned"], true);
    assert_eq!(listed["shape"], format!("{} bytes", big.len()));
}

#[test]
fn a_value_on_the_read_chunk_edge_counts_once() {
    let mut data = vec![b'x'; (1 << 20) - 5];
    data.extend_from_slice(format!(" {VALUE} \n").as_bytes());
    let dir = tree(&[("t/a.jsonl", &data)]);
    let report = json(&scan(&dir, &["t", "--json"]));
    assert_eq!(report["leaks"][0]["strict"], 1);
    assert_eq!(report["leaks"][0]["loose"], 0);
}

#[test]
fn every_text_form_is_matched_whatever_the_case_of_its_extension() {
    for name in ["a.csv", "a.tsv", "a.jsonl", "a.ndjson", "a.CSV"] {
        let dir = tree(&[(&format!("t/{name}"), format!("x {VALUE}\n").as_bytes())]);
        let run = scan(&dir, &["t", "--json"]);
        assert_eq!(run.code, 1, "{name}");
        assert_eq!(json(&run)["data_files"][0]["scanned"], true, "{name}");
    }
}

#[test]
fn a_text_form_that_is_not_utf8_is_still_matched() {
    let mut data = b"caf\xe9,".to_vec();
    data.extend_from_slice(VALUE.as_bytes());
    let dir = tree(&[("t/latin.csv", &data)]);
    let run = scan(&dir, &["t", "--json"]);
    assert_eq!(run.code, 1);
    assert_eq!(json(&run)["skipped"]["non_utf8"], 0);
}

#[test]
fn utf16_cannot_be_matched_so_it_is_unscanned_rather_than_clean() {
    let data: Vec<u8> = VALUE.bytes().flat_map(|b| [b, 0]).collect();
    let dir = tree(&[("t/ok.md", b"fine\n"), ("t/wide.csv", &data)]);
    let run = scan(&dir, &["t", "--json"]);
    assert_eq!(run.code, 3);
    assert_eq!(entry(&json(&run), "t/wide.csv")["scanned"], false);
}

#[test]
fn other_forms_are_listed_by_extension_and_size_and_their_bytes_are_never_read() {
    for ext in UNSCANNED {
        let name = format!("t/a.{ext}");
        let body = format!("{VALUE} qhost.internal\n");
        let dir = tree(&[("t/ok.md", b"fine\n"), (&name, body.as_bytes())]);
        let run = scan(&dir, &["t", "--json"]);
        let report = json(&run);
        assert_eq!(run.code, 3, "{ext}");
        assert_eq!(report["leaks"], serde_json::json!([]), "{ext}");
        assert_eq!(report["candidates_total"], 0, "{ext}");
        assert_eq!(report["files_scanned"], 1, "{ext}");
        assert_eq!(report["skipped"]["binary"], 0, "{ext}");
        let listed = entry(&report, &name);
        assert_eq!(listed["format"], *ext);
        assert_eq!(listed["shape"], format!("{} bytes", body.len()));
        assert_eq!(listed["scanned"], false);
        assert!(run.stderr.contains("unscanned: this is not a clean result"), "{}", run.stderr);
    }
}

#[test]
fn an_unscanned_form_is_listed_from_metadata_even_when_its_bytes_cannot_be_opened() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tree(&[("t/ok.md", b"fine\n"), ("t/a.parquet", b"PAR1")]);
    let path = dir.path().join("t/a.parquet");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    let run = scan(&dir, &["t", "--json"]);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(entry(&json(&run), "t/a.parquet")["shape"], "4 bytes");
}

#[test]
fn unscanned_never_reads_as_clean_and_a_leak_still_wins() {
    let only = tree(&[("t/a.parquet", b"PAR1")]);
    assert_eq!(scan(&only, &["t"]).code, 3);

    let mixed = tree(&[("t/ok.md", b"fine\n"), ("t/a.parquet", b"PAR1")]);
    let run = scan(&mixed, &["t"]);
    assert_eq!(run.code, 3);
    assert!(run.stdout.contains("0 matched for known values, 1 unscanned: not a clean result"), "{}", run.stdout);

    let leak = tree(&[("t/ok.md", VALUE.as_bytes()), ("t/a.parquet", b"PAR1")]);
    assert_eq!(scan(&leak, &["t"]).code, 1);

    let clean = tree(&[("t/ok.md", b"fine\n"), ("t/a.csv", b"a,b\n")]);
    assert_eq!(scan(&clean, &["t"]).code, 0);
}

#[test]
fn a_path_holding_a_known_value_is_redacted_outside_full() {
    let name = format!("t/{VALUE}/{VALUE}.parquet");
    let dir = tree(&[("t/ok.md", b"fine\n"), (&name, b"PAR1")]);

    let run = scan(&dir, &["t", "--json"]);
    assert_eq!(run.code, 1);
    assert!(!run.stdout.contains(VALUE), "{}", run.stdout);
    entry(&json(&run), "t/$KEY_A/$KEY_A.parquet");

    let text = scan(&dir, &["t"]);
    assert!(!text.stdout.contains(VALUE), "{}", text.stdout);
    assert!(text.stdout.contains("t/$KEY_A/$KEY_A.parquet"), "{}", text.stdout);

    let full = scan(&dir, &["t", "--json", "--full"]);
    entry(&json(&full), &name);
}

#[test]
fn a_directory_named_like_a_data_file_and_secret_names_are_not_listed() {
    let dir = tree(&[("t/dir.csv/note.md", b"fine\n"), ("t/.env.csv", VALUE.as_bytes())]);
    let run = scan(&dir, &["t", "--json"]);
    let report = json(&run);
    assert_eq!(run.code, 0);
    assert_eq!(report["data_files"], serde_json::json!([]));
    assert_eq!(report["skipped"]["secret_named"], 1);
}

#[test]
fn full_lists_every_line_of_a_data_file_and_the_default_caps_them() {
    let rows = format!("{VALUE}\n").repeat(5);
    let dir = tree(&[("t/a.csv", rows.as_bytes())]);
    let capped = json(&scan(&dir, &["t", "--json"]));
    assert_eq!(capped["leaks"][0]["strict"], 5);
    assert_eq!(capped["leaks"][0]["at"].as_array().unwrap().len(), 3);
    let full = json(&scan(&dir, &["t", "--json", "--full"]));
    assert_eq!(full["leaks"][0]["at"].as_array().unwrap().len(), 5);
}

fn position(text: &str, needle: &str) -> usize {
    text.find(needle).unwrap_or_else(|| panic!("{needle} missing from:\n{text}"))
}

#[test]
fn the_text_report_names_the_tier_then_leaks_data_files_and_candidates() {
    let notes = format!("{VALUE} and qhost.internal\n");
    let dir = tree(&[("t/notes.md", notes.as_bytes()), ("t/a.parquet", b"PAR1")]);
    let run = scan(&dir, &["t"]);
    let out = &run.stdout;
    assert_eq!(run.code, 1);
    assert!(out.starts_with("tier: plain\n"), "{out}");
    let leaks = position(out, "LEAKS  1 hits across 1 keys");
    let data = position(out, "DATA FILES  ");
    let candidates = position(out, "CANDIDATES  1 (top 1 by weight, then spread)  hostname 1");
    assert!(leaks < data && data < candidates, "{out}");
    assert!(out.contains("KEY_A"), "{out}");
    assert!(out.contains("qh...(14)"), "{out}");
    assert!(!out.contains(VALUE) && !out.contains("qhost"), "{out}");
}

#[test]
fn the_text_report_caps_unscanned_files_and_says_so() {
    let names: Vec<String> = (0..25).map(|i| format!("t/f{i:02}.db")).collect();
    let files: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &b"x"[..])).collect();
    let dir = tree(&files);
    let out = scan(&dir, &["t"]).stdout;
    assert!(out.contains("and 5 more unscanned; --json lists them all"), "{out}");
    assert!(!out.contains("t/f24.db"), "{out}");
    assert!(scan(&dir, &["t", "--full"]).stdout.contains("t/f24.db"));
    assert_eq!(json(&scan(&dir, &["t", "--json"]))["data_files"].as_array().unwrap().len(), 25);
}

#[test]
fn the_extractor_errors_line_only_appears_when_there_are_errors() {
    let dir = tree(&[("t/ok.md", b"fine\n")]);
    assert!(!scan(&dir, &["t"]).stdout.contains("EXTRACTOR ERRORS"));
}
