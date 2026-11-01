//! What a live run does at its limits: over-long requests, over-cap files, values that never get
//! a verdict, and values the vendor rejects. The binary against a loopback stub.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

const OVER_LIMIT: &str = r#"{"detail":{"error_type":"max_tokens_exceeded"}}"#;
const LIVE: &str = "live (jev-1.14.0)";

/// A named file holding one hostname nobody could mistake for another test's.
const GOOD: (&str, &str) = ("good.md", "connect to zqx-etl-07.corp.quillon-partners.lan\n");

struct World {
    root: TempDir,
    home: TempDir,
}

fn world(files: &[(&str, &str)]) -> World {
    let root = TempDir::new().unwrap();
    for (name, text) in files {
        fs::write(root.path().join(name), text).unwrap();
    }
    fs::write(root.path().join("rules.env"), "UNRELATED=zqxunrelatedvalue\n").unwrap();
    let home = TempDir::new().unwrap();
    fs::create_dir_all(home.path().join(".config/envscan")).unwrap();
    fs::write(home.path().join(".config/envscan/config.toml"), "tier = \"live\"\n").unwrap();
    World { root, home }
}

type Rule = Arc<dyn Fn(&Value) -> (u16, String) + Send + Sync>;

/// Every request the stub received.
type Requests = Arc<Mutex<Vec<Value>>>;

fn stub(rule: impl Fn(&Value) -> (u16, String) + Send + Sync + 'static) -> (String, Requests) {
    let rule: Rule = Arc::new(rule);
    let seen: Requests = Arc::default();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}/v1/systemone", listener.local_addr().unwrap().port());
    let shared = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let (rule, seen) = (rule.clone(), shared.clone());
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut writer = stream;
                loop {
                    let mut length = 0;
                    loop {
                        let mut header = String::new();
                        if reader.read_line(&mut header).unwrap_or(0) == 0 {
                            return;
                        }
                        let header = header.trim_end().to_ascii_lowercase();
                        if header.is_empty() {
                            break;
                        }
                        if let Some(value) = header.strip_prefix("content-length:") {
                            length = value.trim().parse().unwrap();
                        }
                    }
                    let mut body = vec![0; length];
                    reader.read_exact(&mut body).unwrap();
                    let request: Value = serde_json::from_slice(&body).unwrap();
                    let (status, text) = rule(&request);
                    seen.lock().unwrap().push(request);
                    write!(writer, "HTTP/1.1 {status} X\r\nContent-Length: {}\r\n\r\n{text}", text.len()).unwrap();
                    writer.flush().unwrap();
                }
            });
        }
    });
    (url, seen)
}

/// The values one request asks about, in question order.
fn values(request: &Value) -> Vec<String> {
    let questions = request["questions"].as_object().unwrap();
    (0..)
        .map_while(|i| questions.get(&format!("c{i}__private")))
        .map(|q| q["instructions"].as_str().unwrap().split('`').nth(1).unwrap().to_string())
        .collect()
}

/// A well-formed answer giving each value the p this function picks.
fn answer(request: &Value, p: impl Fn(&str) -> f64) -> (u16, String) {
    let mut answers = serde_json::Map::new();
    for (i, value) in values(request).iter().enumerate() {
        answers.insert(format!("c{i}__private"), json!({"noul": p(value)}));
        answers.insert(format!("c{i}__kind"), json!({"choice": "other"}));
    }
    (200, json!({"answers": answers}).to_string())
}

fn scan(world: &World, url: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_envscan"))
        .current_dir(world.root.path())
        .args(["scan", "--env", "rules.env", "--json"])
        .args(args)
        .env("HOME", world.home.path())
        .env("TYPESAFE_API_KEY", "stub-key-not-a-secret")
        .env("ENVSCAN_JEV_ENDPOINT", url)
        .output()
        .unwrap()
}

fn report(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stderr)))
}

fn listed<'a>(report: &'a Value, list: &str) -> &'a Vec<Value> {
    report[list].as_array().unwrap_or_else(|| panic!("no {list} list in {report}"))
}

fn with_reason<'a>(report: &'a Value, reason: &str) -> Vec<&'a Value> {
    listed(report, "unjudged").iter().filter(|u| u["reason"] == reason).collect()
}

fn full_values(list: &[Value]) -> Vec<&str> {
    list.iter().map(|c| c["value"].as_str().unwrap()).collect()
}

/// Whether any request's line held this text.
fn sent_line(seen: &Requests, needle: &str) -> bool {
    seen.lock().unwrap().iter().any(|r| r["state"]["line"].as_str().unwrap().contains(needle))
}

#[test]
fn a_known_only_files_candidates_stay_visible_in_a_live_report() {
    let world = world(&[GOOD, ("other.ini", "host = zqx-known-only.corp.quillon-partners.lan\n")]);
    let (url, seen) = stub(|r| answer(r, |_| 0.9));
    let out = scan(&world, &url, &["--full", "good.md", "other.ini"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("zqx-known-only"), "the candidate is gone from the report:\n{stdout}");

    let report = report(&out);
    assert_eq!(report["tier"], LIVE);
    assert!(!sent_line(&seen, "zqx-known-only"));
    let unjudged = with_reason(&report, "known-only-file");
    assert_eq!(unjudged.len(), 1);
    assert_eq!(unjudged[0]["kind"], "hostname");
    assert_eq!(unjudged[0]["first"], "other.ini:1");
    // One report's judged list never mixes in unjudged candidates.
    assert!(listed(&report, "candidates").iter().all(|c| c.get("p").is_some()));
}

#[test]
fn an_unjudged_value_is_masked_outside_full() {
    let world = world(&[GOOD, ("other.ini", "host = zqx-known-only.corp.quillon-partners.lan\n")]);
    let (url, _) = stub(|r| answer(r, |_| 0.9));
    let out = scan(&world, &url, &["good.md", "other.ini"]);
    assert!(!String::from_utf8_lossy(&out.stdout).contains("zqx-known-only"));
    let report = report(&out);
    let unjudged = with_reason(&report, "known-only-file");
    assert!(unjudged[0].get("value").is_none());
    assert_eq!(unjudged[0]["masked"], "zq...(40)");
}

#[test]
fn the_392_ip_line_ends_live_with_every_value_judged_in_order() {
    let ips: Vec<String> = (0..392).map(|i| format!("10.0.{}.{}", i / 250, i % 250)).collect();
    let line = ips.join(" ");
    assert!(line.len() <= 4096, "{}", line.len());
    let world = world(&[("bad.md", &format!("{line}\n"))]);
    // As the vendor does: too many values on one request is a 400. 80 is its edge at 13 kinds and
    // 824 tokens each. An even last octet scores high, so a misaligned merge shows.
    let (url, seen) = stub(|r| {
        if values(r).len() > 80 {
            return (400, OVER_LIMIT.to_string());
        }
        answer(r, |v| if v.rsplit('.').next().unwrap().parse::<u32>().unwrap() % 2 == 0 { 0.9 } else { 0.1 })
    });
    let out = scan(&world, &url, &["--full", "bad.md"]);
    let report = report(&out);
    assert_eq!(report["tier"], LIVE, "{}", String::from_utf8_lossy(&out.stderr));
    assert!(seen.lock().unwrap().len() > 1, "one request cannot hold them");
    assert_eq!(report["judgement"]["candidates_sent"], 392);
    assert_eq!(report["judgement"]["lines_sent"], 1);
    assert_eq!(with_reason(&report, "over-limit-line").len(), 0);
    let even = |v: &&str| v.rsplit('.').next().unwrap().parse::<u32>().unwrap() % 2 == 0;
    let kept = full_values(listed(&report, "candidates"));
    let rejected = full_values(listed(&report, "rejected"));
    assert_eq!(kept.len() + rejected.len(), 392);
    assert!(kept.iter().all(|v| even(v)), "a verdict landed on the wrong value");
    assert!(!rejected.iter().any(|v| even(v)), "a verdict landed on the wrong value");
}

#[test]
fn a_stubbed_over_limit_line_is_unjudged_and_the_run_continues() {
    let world = world(&[GOOD, ("long.md", "zqx-too-long.corp.quillon-partners.lan and 10.9.8.7\n")]);
    let (url, _) = stub(|r| {
        if r["state"]["line"].as_str().unwrap().contains("zqx-too-long") {
            return (400, OVER_LIMIT.to_string());
        }
        answer(r, |_| 0.9)
    });
    let out = scan(&world, &url, &["--full", "good.md", "long.md"]);
    assert_eq!(out.status.code(), Some(0));
    let report = report(&out);
    assert_eq!(report["tier"], LIVE);
    let unjudged = with_reason(&report, "over-limit-line");
    assert_eq!(unjudged.len(), 2);
    assert!(unjudged.iter().all(|u| u["first"] == "long.md:1"));
    assert_eq!(full_values(listed(&report, "candidates")), ["zqx-etl-07.corp.quillon-partners.lan"]);
    assert_eq!(report["judgement"]["kept"], 1);
}

#[test]
fn every_other_failure_still_fails_the_whole_run() {
    type Case = (fn(&Value) -> (u16, String), &'static str);
    let cases: [Case; 4] = [
        (|_| (500, String::new()), "http 500"),
        (|_| (401, String::new()), "http 401"),
        (|_| (400, r#"{"detail":{"error_type":"other"}}"#.to_string()), "http 400"),
        (|r| answer(r, |_| 1.4), "bad response"),
    ];
    for (rule, reason) in cases {
        let world = world(&[GOOD]);
        let (url, _) = stub(rule);
        let out = scan(&world, &url, &["good.md"]);
        assert_eq!(out.status.code(), Some(0));
        let report = report(&out);
        assert_eq!(report["tier"].as_str().unwrap(), format!("plain (fallback from live: {reason})"));
        assert!(report.get("judgement").is_none());
        assert!(report.get("unjudged").is_none());
        assert!(report["candidates_total"].as_u64().unwrap() > 0);
    }
}

#[test]
fn a_file_over_its_cap_sends_nothing_and_the_rest_proceeds() {
    let world = world(&[GOOD, ("many.md", "10.1.1.1 10.1.1.2\n10.1.1.3\n10.1.1.4 10.1.1.5 10.1.1.6\n")]);
    let (url, seen) = stub(|r| answer(r, |_| 0.9));
    let out = scan(&world, &url, &["--full", "--max-file-candidates", "5", "good.md", "many.md"]);
    let report = report(&out);
    assert_eq!(report["tier"], LIVE);
    assert!(!sent_line(&seen, "10.1.1."));
    assert_eq!(with_reason(&report, "over-cap-file").len(), 6);
    assert_eq!(report["judgement"]["candidates_sent"], 1);
    assert_eq!(full_values(listed(&report, "candidates")), ["zqx-etl-07.corp.quillon-partners.lan"]);

    // At the cap, not over it, is judged.
    let (url, seen) = stub(|r| answer(r, |_| 0.9));
    let report = self::report(&scan(&world, &url, &["--full", "--max-file-candidates", "6", "good.md", "many.md"]));
    assert!(sent_line(&seen, "10.1.1."));
    assert_eq!(with_reason(&report, "over-cap-file").len(), 0);
}

#[test]
fn the_same_line_in_a_capped_file_is_still_judged_for_the_other_file() {
    let world = world(&[("a.md", "10.1.1.1 10.1.1.2\n"), ("b.md", "10.1.1.1 10.1.1.2\n10.1.1.3\n")]);
    let (url, seen) = stub(|r| answer(r, |_| 0.9));
    let report = report(&scan(&world, &url, &["--full", "--max-file-candidates", "2", "a.md", "b.md"]));
    assert_eq!(seen.lock().unwrap().iter().filter(|r| r["state"]["file"] == "b.md").count(), 0);
    assert_eq!(report["judgement"]["candidates_sent"], 2);
    assert_eq!(listed(&report, "candidates").len(), 2);
    assert_eq!(with_reason(&report, "over-cap-file").len(), 3);
}

#[test]
fn the_whole_run_limit_fails_before_sending_and_prints_the_estimate() {
    let world = world(&[("many.md", "10.1.1.1 10.1.1.2\n")]);
    let (url, seen) = stub(|r| answer(r, |_| 0.9));
    let out = scan(&world, &url, &["--max-candidates", "1", "many.md"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("2 candidates, about $"));
    assert_eq!(report(&out)["tier"], "plain (fallback from live: 2 candidates, limit 1)");
    assert_eq!(seen.lock().unwrap().len(), 0);

    let out = scan(&world, &url, &["--max-candidates", "0", "many.md"]);
    assert_eq!(report(&out)["tier"], "plain (fallback from live: 2 candidates, limit 0)");
    assert_eq!(seen.lock().unwrap().len(), 0);
}

#[test]
fn the_defaults_are_the_documented_ones() {
    let out = Command::new(env!("CARGO_BIN_EXE_envscan")).args(["scan", "--help"]).output().unwrap();
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("[default: 25000]"), "{help}");
    assert!(help.contains("[default: 5000]"), "{help}");
}

#[test]
fn log_json_and_diff_are_sent_and_extensionless_files_are_not() {
    let line = |host: &str| format!("host {host}.corp.quillon-partners.lan\n");
    let (a, b, c, d, e) = (line("zqx-log"), line("zqx-json"), line("zqx-diff"), line("zqx-docker"), line("zqx-example"));
    let world = world(&[("a.log", &a), ("a.json", &b), ("a.diff", &c), ("Dockerfile", &d), (".env.example", &e)]);
    let (url, seen) = stub(|r| answer(r, |_| 0.9));
    let report = report(&scan(&world, &url, &["--full", "a.log", "a.json", "a.diff", "Dockerfile", ".env.example"]));
    for sent in ["zqx-log", "zqx-json", "zqx-diff"] {
        assert!(sent_line(&seen, sent), "{sent}");
    }
    for kept_back in ["zqx-docker", "zqx-example"] {
        assert!(!sent_line(&seen, kept_back), "{kept_back}");
    }
    assert_eq!(with_reason(&report, "known-only-file").len(), 2);
    assert_eq!(report["judgement"]["files_known_only"], 2);
}

#[test]
fn specific_shapes_survive_a_rejection_and_the_others_drop() {
    // Assembled here so the repo holds no literal home path or email.
    let text = format!(
        "10.2.3.4 zq{at}quillon-partners.dev /{home}/zq/notes gs://zqx-bucket github.com/zqx/widget 123456789012 some-slug-name Quillon Partners\n",
        at = "@",
        home = "home",
    );
    let world = world(&[("a.md", &text)]);
    let (url, _) = stub(|r| answer(r, |_| 0.1));
    let out = scan(&world, &url, &["--full", "a.md"]);
    let report = report(&out);
    assert_eq!(report["tier"], LIVE);
    let rejected = listed(&report, "rejected");
    let mut kinds: Vec<&str> = rejected.iter().map(|c| c["kind"].as_str().unwrap()).collect();
    kinds.sort_unstable();
    assert_eq!(kinds, ["account-id", "bucket", "email", "gh-repo", "home-path", "ip"]);
    assert!(rejected.iter().all(|c| c["p"] == 0.1 && c["judged_kind"] == "other"));
    // `kept` and `rejected` still count verdicts, and the kept list still means kept.
    let sent = report["judgement"]["candidates_sent"].as_u64().unwrap();
    assert!(sent > 6, "{sent}");
    assert_eq!(report["judgement"]["kept"], 0);
    assert_eq!(report["judgement"]["rejected"], sent);
    assert_eq!(report["judgement"]["rejected_listed"], 6);
    assert_eq!(listed(&report, "candidates").len(), 0);
    assert_eq!(report["candidates_total"], 0);
}

#[test]
fn exactly_the_threshold_counts_as_rejected() {
    let world = world(&[("a.md", "10.2.3.4\n")]);
    let (url, _) = stub(|r| answer(r, |_| 0.3));
    let report = report(&scan(&world, &url, &["--full", "a.md"]));
    assert_eq!(listed(&report, "rejected").len(), 1);
    assert_eq!(report["judgement"]["kept"], 0);
}

#[test]
fn the_text_report_shows_both_lists_and_a_plain_run_has_neither() {
    let world = world(&[("a.md", "10.2.3.4\n"), ("other.ini", "host = zqx-known-only.corp.quillon-partners.lan\n")]);
    let (url, _) = stub(|r| answer(r, |_| 0.1));
    let out = Command::new(env!("CARGO_BIN_EXE_envscan"))
        .current_dir(world.root.path())
        .args(["scan", "--env", "rules.env", "a.md", "other.ini"])
        .env("HOME", world.home.path())
        .env("TYPESAFE_API_KEY", "stub-key-not-a-secret")
        .env("ENVSCAN_JEV_ENDPOINT", &url)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("REJECTED  1"), "{text}");
    assert!(text.contains("UNJUDGED  1"), "{text}");
    assert!(text.contains("known-only-file"), "{text}");
    assert!(!text.contains("zqx-known-only"), "{text}");

    let (url, _) = stub(|r| answer(r, |_| 0.1));
    let plain = report(&scan(&world, &url, &["--known-only", "a.md"]));
    assert!(plain.get("unjudged").is_none() && plain.get("rejected").is_none());
}

#[test]
fn a_withheld_line_keeps_its_handling() {
    let world = world(&[("a.md", "zqxunrelatedvalue beside 10.2.3.4\n")]);
    let (url, seen) = stub(|r| answer(r, |_| 0.1));
    let report = report(&scan(&world, &url, &["--full", "a.md"]));
    assert_eq!(seen.lock().unwrap().len(), 0);
    assert_eq!(report["judgement"]["lines_withheld"], 1);
    assert_eq!(listed(&report, "unjudged").len(), 0);
    let by_value: HashMap<&str, &Value> = listed(&report, "candidates").iter().map(|c| (c["value"].as_str().unwrap(), c)).collect();
    assert!(by_value["10.2.3.4"].get("p").is_none());
}
