//! The extractor against its Python golden, and as a caller of `envscan scan` sees it.
//! Goldens come from `tests/fixtures/broad/golden.py`; see the README beside it.

use envscan::extract::{extract, lines, Found, MAX_LINE_BYTES};
use rayon::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const VALUE: &str = "zqxvalue";

fn broad() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/broad")
}

fn home() -> String {
    format!("/{}", "home")
}

fn users() -> String {
    format!("/{}", "Users")
}

fn pairs(line: &str) -> Vec<(String, String)> {
    let out = extract(line);
    assert_eq!(out.errors, 0, "runtime error on a line of {} bytes", line.len());
    out.found.into_iter().map(|Found { value, shape }| (value, shape.to_string())).collect()
}

#[test]
fn the_fixture_equals_the_python_golden() {
    let mut golden: Vec<Value> = fs::read_to_string(broad().join("expected.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    golden.reverse();
    let mut compared = 0;
    let mut files = Vec::new();
    for dir in ["config", "logs", "notes", "scripts"] {
        for entry in fs::read_dir(broad().join("fixture").join(dir)).unwrap() {
            files.push(format!("{dir}/{}", entry.unwrap().file_name().to_string_lossy()));
        }
    }
    files.sort();
    assert_eq!(files.len(), 7);
    for rel in files {
        let text = fs::read_to_string(broad().join("fixture").join(&rel))
            .unwrap()
            .replace("<HOME>", &home())
            .replace("<USERS>", &users())
            .replace("<AT>", "@");
        for (i, line) in lines(&text).enumerate() {
            let got = pairs(line);
            if got.is_empty() {
                continue;
            }
            let want = golden.pop().unwrap_or_else(|| panic!("no golden for {rel}:{}", i + 1));
            assert_eq!((want["file"].as_str().unwrap(), want["line"].as_u64().unwrap()), (rel.as_str(), i as u64 + 1));
            let want: Vec<(String, String)> = want["found"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| {
                    let value = p[0].as_str().unwrap().replace("<HOME>", &home()).replace("<USERS>", &users()).replace("<AT>", "@");
                    (value, p[1].as_str().unwrap().to_string())
                })
                .collect();
            assert_eq!(got, want, "{rel}:{}", i + 1);
            compared += got.len();
        }
    }
    assert!(golden.is_empty(), "the golden has lines the port found nothing on: {:?}", golden.last());
    // The Python counter reports 92 on the fixture this one is renamed from.
    assert_eq!(compared, 92);
}

struct Lcg(u64);

impl Lcg {
    fn next(&mut self, bound: u64) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.0 >> 33) % bound
    }
}

fn fuzz_line(rng: &mut Lcg, fragments: &[String]) -> String {
    let mut out = String::new();
    for _ in 0..rng.next(12) + 1 {
        if rng.next(3) == 0 {
            for _ in 0..rng.next(6) + 1 {
                let c = rng.next(127) as u8;
                out.push(if c == 10 { ' ' } else { c as char });
            }
        } else {
            out.push_str(&fragments[rng.next(fragments.len() as u64) as usize]);
        }
    }
    if out.ends_with('\r') {
        out.pop();
    }
    out
}

fn fnv(data: &[u8], mut h: u64) -> u64 {
    for b in data {
        h = (h ^ *b as u64).wrapping_mul(0x100000001b3);
    }
    h
}

/// Each sum folds the ordered `(value, shape)` list of every line so far, so the first differing
/// sum places a divergence within 1,000 lines, and a run of golden.py with that block printed
/// names it.
#[test]
fn two_hundred_thousand_ascii_fuzz_lines_equal_the_python_golden() {
    let mut fragments: Vec<String> = ["gs://", "s3://", "://", "http://", "github.com/"].map(String::from).to_vec();
    fragments.push(format!("{}/", home()));
    fragments.push(format!("{}/", users()));
    fragments.extend(
        [
            "@", ".", "-", "_", "/", " ", ".csv", ".txt", ".pdf", ".lan", ".internal", ".corp", ".local", ".com",
            "10.20.30.41", "1.2.3", "/24", "123456789012", "Quill", "Quill Feather", "Session", "The", "foo", "bar",
            "a-b", "x/y",
        ]
        .map(String::from),
    );
    let mut rng = Lcg(0x2545F4914F6CDD1D);
    let input: Vec<String> = (0..200_000).map(|_| fuzz_line(&mut rng, &fragments)).collect();
    let results: Vec<Vec<(String, String)>> = input.par_iter().map(|l| pairs(l)).collect();

    let want = fs::read_to_string(broad().join("fuzz.sums")).unwrap();
    let want: Vec<&str> = want.lines().collect();
    assert_eq!(want.len(), 200);
    let mut h = 0xcbf29ce484222325;
    for (i, found) in results.iter().enumerate() {
        for (value, shape) in found {
            h = fnv(format!("{value}\0{shape}\0").as_bytes(), h);
        }
        h = fnv(b"\n", h);
        if (i + 1) % 1000 == 0 {
            assert_eq!(format!("{h:016x}"), want[i / 1000], "diverged at or before line {}", i + 1);
        }
    }
}

/// Accepted differences. Python's `\w` is "alphanumeric or `_`", Rust's is Unicode's word class,
/// so marks, joiners and connectors differ one way and superscript digits the other. Each row
/// gives what Python returns; the port's result is pinned so a change shows up here.
#[test]
fn non_ascii_differences_in_word_characters_are_listed() {
    for (line, port, python) in [
        // U+0301, a combining mark: a word character in Rust only, so `\b` differs.
        ("abc Quillon\u{301}", vec![], vec![("Quillon", "proper-noun")]),
        // U+200D, a joiner.
        ("abc Quillon\u{200d}", vec![], vec![("Quillon", "proper-noun")]),
        // U+203F, a connector.
        ("abc Quillon\u{203f}", vec![], vec![("Quillon", "proper-noun")]),
        // U+00B2, a digit to Python's isalnum and not to Rust's class.
        ("abc Quillon\u{b2}", vec![("Quillon", "proper-noun")], vec![]),
    ] {
        let want: Vec<(String, String)> = port.iter().map(|(v, s): &(&str, &str)| (v.to_string(), s.to_string())).collect();
        assert_eq!(pairs(line), want, "{line:?}");
        assert_ne!(port, python, "a row with no difference does not belong here");
    }
}

#[test]
fn every_ascii_separator_python_treats_as_space_ends_a_home_path() {
    for c in ['\x1c', '\x1d', '\x1e', '\x1f', '\x0b', '\x0c'] {
        let got = pairs(&format!("{}/a{c}b", home()));
        assert_eq!(got, vec![(format!("{}/a", home()), "home-path".to_string())], "{c:?}");
    }
}

#[test]
fn lines_split_on_newline_with_a_trailing_return_removed() {
    let got: Vec<&str> = lines("a\r\nb\rc\n\x0bd\n").collect();
    assert_eq!(got, ["a", "b\rc", "\x0bd"]);
}

/// The slowest shapes a line under the cap can hold. Python took 24 s on 40 KB of the first.
#[test]
fn a_hostile_line_at_the_cap_ends_quickly_and_reports_any_error() {
    for unit in ["a.", "a-", "1.", "a/", "@a", "Aaaa "] {
        let line = unit.repeat(MAX_LINE_BYTES / unit.len());
        let started = Instant::now();
        let out = extract(&line);
        assert!(started.elapsed() < Duration::from_secs(10), "{unit}: {:?}", started.elapsed());
        eprintln!("{unit:?}: {:?}, errors {}, found {}", started.elapsed(), out.errors, out.found.len());
    }
}

struct Run {
    code: i32,
    stdout: String,
}

fn scan(dir: &Path, args: &[&str]) -> Run {
    let out = Command::new(env!("CARGO_BIN_EXE_envscan"))
        // No saved tier: an operator's `live` must never send fixture lines.
        .env("HOME", "/nonexistent-envscan-test-home")
        .arg("scan")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    Run { code: out.status.code().unwrap(), stdout: String::from_utf8(out.stdout).unwrap() }
}

fn json(run: &Run) -> Value {
    serde_json::from_str(&run.stdout).unwrap()
}

fn tree(files: &[(&str, &str)]) -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join(".env"), format!("KEY={VALUE}\n")).unwrap();
    for (name, text) in files {
        fs::write(dir.path().join(name), text).unwrap();
    }
    dir
}

const ARGS: &[&str] = &[".", "--env", ".env", "--json"];

#[test]
fn candidates_fill_the_report_masked_ranked_and_counted() {
    let dir = tree(&[
        ("a.md", "see db1.internal and some-slug\nsome-slug again\n"),
        ("b.md", &format!("some-slug and ops{}zqxmail.example\n", '@')),
    ]);
    let run = scan(dir.path(), ARGS);
    assert_eq!(run.code, 0, "candidates alone are not leaks");
    let report = json(&run);
    assert_eq!(report["candidates_total"], 3);
    assert_eq!(report["candidates_by_kind"]["slug"], 1);
    let rows = report["candidates"].as_array().unwrap();
    let kinds: Vec<&str> = rows.iter().map(|c| c["kind"].as_str().unwrap()).collect();
    assert_eq!(kinds, ["email", "hostname", "slug"], "weight first");
    let slug = &rows[2];
    assert_eq!((slug["masked"].as_str().unwrap(), &slug["files"], &slug["hits"]), ("so...(9)", &2.into(), &3.into()));
    assert_eq!(slug["first"], "a.md:1");
    assert!(slug.get("value").is_none());
    for text in ["db1.internal", "some-slug", "zqxmail"] {
        assert!(!run.stdout.contains(text), "{text}");
    }
    assert!(!scan(dir.path(), &[".", "--env", ".env"]).stdout.contains("some-slug"));
}

#[test]
fn spread_breaks_a_weight_tie_and_top_caps_the_list_not_the_total() {
    let dir = tree(&[("a.md", "one-slug two-slug\n"), ("b.md", "two-slug\n")]);
    let run = scan(dir.path(), &[".", "--env", ".env", "--json", "--top", "1"]);
    let report = json(&run);
    assert_eq!(report["candidates_total"], 2);
    let rows = report["candidates"].as_array().unwrap();
    assert_eq!((rows.len(), rows[0]["masked"].as_str().unwrap()), (1, "tw...(8)"));
}

#[test]
fn full_lists_every_value_and_location() {
    let dir = tree(&[("a.md", "one-slug\none-slug\n")]);
    let report = json(&scan(dir.path(), &[".", "--env", ".env", "--json", "--full", "--top", "0"]));
    let row = &report["candidates"][0];
    assert_eq!(row["value"], "one-slug");
    assert_eq!(row["at"], serde_json::json!(["a.md:1", "a.md:2"]));
}

#[test]
fn known_only_extracts_nothing_and_still_matches() {
    let dir = tree(&[("a.md", &format!("{VALUE} and some-slug\n"))]);
    let report = json(&scan(dir.path(), &[".", "--env", ".env", "--json", "--known-only"]));
    assert_eq!(report["candidates_total"], 0);
    assert_eq!(report["leaks"][0]["key"], "KEY");
}

#[test]
fn candidates_still_print_when_no_rules_load() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join(".env"), "").unwrap();
    fs::write(dir.path().join("a.md"), "some-slug\n").unwrap();
    let run = scan(dir.path(), ARGS);
    assert_eq!(run.code, 2);
    assert_eq!(json(&run)["candidates_total"], 1);
}

#[test]
fn a_long_line_gets_known_value_matching_only_and_is_counted() {
    let at_cap = format!("{}{}", "x ".repeat((MAX_LINE_BYTES - 9) / 2), " at-slug");
    assert!(at_cap.len() <= MAX_LINE_BYTES);
    let over = format!("{} over-slug {VALUE}", "x ".repeat(MAX_LINE_BYTES / 2));
    let dir = tree(&[("a.md", &format!("{at_cap}\n{over}\n"))]);
    let run = scan(dir.path(), ARGS);
    assert_eq!(run.code, 1, "the known value on the long line still counts");
    let report = json(&run);
    assert_eq!(report["skipped"]["long_lines"], 1);
    assert_eq!(report["candidates_total"], 1);
    assert_eq!(report["candidates"][0]["masked"], "at...(7)");
}

/// `fancy-regex` gives up on its backtrack limit below the line cap, where Python would carry on.
#[test]
fn a_runtime_error_on_a_real_line_reaches_the_report() {
    let dir = tree(&[("a.md", &format!("{}\nsome-slug\n", "a.".repeat(MAX_LINE_BYTES / 2)))]);
    let run = scan(dir.path(), ARGS);
    assert_eq!(run.code, 0, "the exit code does not change");
    let report = json(&run);
    assert_eq!(report["extractor_errors"], 3);
    assert_eq!(report["candidates_total"], 1);
    assert!(scan(dir.path(), &[".", "--env", ".env"]).stdout.contains("EXTRACTOR ERRORS  3"));
}

#[test]
fn a_candidate_holding_a_known_value_is_a_leak_and_not_a_candidate() {
    let dir = tree(&[("a.md", &format!("https://{VALUE}.example/x\nother-slug\n"))]);
    let run = scan(dir.path(), ARGS);
    assert_eq!(run.code, 1);
    let report = json(&run);
    assert_eq!(report["candidates_total"], 1);
    assert_eq!(report["candidates"][0]["kind"], "slug");
}

#[test]
fn a_candidates_first_location_is_shown_by_key() {
    let dir = tree(&[(&format!("{VALUE}.md"), "some-slug\n")]);
    let report = json(&scan(dir.path(), ARGS));
    assert_eq!(report["candidates"][0]["first"], "$KEY.md:1");
}

#[test]
fn stdin_is_extracted_too() {
    let dir = tree(&[]);
    let mut child = Command::new(env!("CARGO_BIN_EXE_envscan"))
        // No saved tier: an operator's `live` must never send fixture lines.
        .env("HOME", "/nonexistent-envscan-test-home")
        .args(["scan", "--stdin", "--env", ".env", "--json"])
        .current_dir(dir.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(&mut child.stdin.take().unwrap(), b"some-slug\n").unwrap();
    let out = child.wait_with_output().unwrap();
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["candidates"][0]["first"], "<stdin>:1");
}

#[test]
fn a_data_file_is_not_extracted_but_is_still_matched() {
    let dir = tree(&[("a.csv", &format!("some-slug,{VALUE}\n")), ("b.jsonl", "{\"a\":\"some-slug\"}\n")]);
    let run = scan(dir.path(), ARGS);
    assert_eq!(run.code, 1);
    assert_eq!(json(&run)["candidates_total"], 0);
}

/// `_` is a boundary, so a known value inside an underscore-joined name is a leak, bare or
/// inside another shape. The shape is then not also a candidate: its mask would print part of
/// the value. A value glued to a letter or digit stays hidden from both.
#[test]
fn a_known_value_in_an_underscore_name_is_a_leak_whatever_shape_holds_it() {
    let v = VALUE;
    for text in [
        format!("x {v}_raw.txt"),
        format!("x gs://{v}_raw"),
        format!("x {}/me/{v}_raw", home()),
        format!("x team/{v}_raw"),
        format!("x {v}_raw{}zqxmail.example", '@'),
        format!("x @{v}_raw"),
        format!("select * from {v}_raw"),
        format!("select * from pre_{v}"),
        format!("{v}_raw_{v}"),
        format!("x Pre_{v}"),
        format!("x pre-{v}_raw"),
    ] {
        let dir = tree(&[("a.md", &format!("{text}\n"))]);
        let run = scan(dir.path(), ARGS);
        assert_eq!(run.code, 1, "{text}");
        let report = json(&run);
        assert_eq!(report["leaks"][0]["key"], "KEY", "{text}");
        assert_eq!(report["candidates_total"], 0, "{text}: {}", report["candidates"]);
    }
    let dir = tree(&[("a.md", &format!("select * from stg_x{v}_raw, {v}2_raw\n"))]);
    let run = scan(dir.path(), ARGS);
    assert_eq!(run.code, 0);
    assert_eq!(json(&run)["leaks"].as_array().unwrap().len(), 0);
}
