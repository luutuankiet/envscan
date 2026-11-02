//! The judgement tier end to end: the binary, a loopback stub replaying recorded verdicts, and
//! the public broad fixture rebuilt in a temp dir. `recorded-p.json` holds one recorded p per
//! fixture candidate, keyed by file, line and value; see `tests/fixtures/judge/README.md`.

use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

const FAKE_KEY: &str = "stub-key-not-a-secret";
const FILES: &[&str] = &[
    "config/pipeline.json",
    "logs/run-1182.log",
    "notes/handoff-bramble.md",
    "notes/scratch-ideas.md",
    "notes/session-2026-10-30.md",
    "scripts/check_hosts.py",
    "scripts/sync_raw.sh",
];

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// The fixture keeps placeholders so the repo holds no literal home path or email.
fn expand(text: &str) -> String {
    text.replace("<HOME>", &format!("/{}", "home")).replace("<USERS>", &format!("/{}", "Users")).replace("<AT>", "@")
}

/// The fixture in a temp dir, with an unrelated rule so the run is not "no rules loaded", and a
/// HOME whose saved tier is `live`.
struct World {
    root: TempDir,
    home: TempDir,
    /// `(file, line text)` to line number, first occurrence.
    line_no: HashMap<(String, String), usize>,
}

fn world(tier: &str) -> World {
    let root = TempDir::new().unwrap();
    let mut line_no = HashMap::new();
    for rel in FILES {
        let text = expand(&fs::read_to_string(fixtures().join("broad/fixture").join(rel)).unwrap());
        for (i, line) in text.split('\n').enumerate() {
            line_no.entry((rel.to_string(), line.trim_end_matches('\r').to_string())).or_insert(i + 1);
        }
        let path = root.path().join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    fs::write(root.path().join("rules.env"), "UNRELATED=zqxunrelatedvalue\n").unwrap();
    let home = TempDir::new().unwrap();
    fs::create_dir_all(home.path().join(".config/envscan")).unwrap();
    fs::write(home.path().join(".config/envscan/config.toml"), format!("tier = \"{tier}\"\n")).unwrap();
    World { root, home, line_no }
}

/// What the stub saw.
#[derive(Default)]
struct Seen {
    files: HashSet<String>,
    requests: usize,
    bad_auth: usize,
    state_keys: HashSet<String>,
    unknown: Vec<String>,
}

/// A loopback HTTP stub answering each request from the recorded p.
fn stub(world: &World) -> (String, Arc<Mutex<Seen>>) {
    let recorded: Vec<Value> =
        serde_json::from_str(&fs::read_to_string(fixtures().join("judge/recorded-p.json")).unwrap()).unwrap();
    let p_of: HashMap<(String, usize, String), f64> = recorded
        .iter()
        .map(|r| {
            let key = (r["file"].as_str().unwrap().to_string(), r["line"].as_u64().unwrap() as usize, expand(r["value"].as_str().unwrap()));
            (key, r["p"].as_f64().unwrap())
        })
        .collect();
    let p_of = Arc::new(p_of);
    let line_no = Arc::new(world.line_no.clone());
    let seen = Arc::new(Mutex::new(Seen::default()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}/v1/systemone", listener.local_addr().unwrap().port());
    let shared = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let (p_of, line_no, seen) = (p_of.clone(), line_no.clone(), shared.clone());
            std::thread::spawn(move || serve(stream, &p_of, &line_no, &seen));
        }
    });
    (url, seen)
}

/// HTTP/1.1 with keep-alive: one connection may carry many requests.
fn serve(stream: TcpStream, p_of: &HashMap<(String, usize, String), f64>, line_no: &HashMap<(String, String), usize>, seen: &Mutex<Seen>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = stream;
    loop {
        let mut length = 0;
        let mut auth = String::new();
        let mut first = true;
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).unwrap_or(0) == 0 {
                return;
            }
            let header = header.trim_end();
            if header.is_empty() && !first {
                break;
            }
            first = false;
            if let Some((name, value)) = header.split_once(':') {
                match name.trim().to_ascii_lowercase().as_str() {
                    "content-length" => length = value.trim().parse().unwrap(),
                    "authorization" => auth = value.trim().to_string(),
                    _ => {}
                }
            }
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        let request: Value = serde_json::from_slice(&body).unwrap();
        let answer = answer(&request, &auth, p_of, line_no, seen);
        let text = answer.to_string();
        write!(writer, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{text}", text.len()).unwrap();
        writer.flush().unwrap();
    }
}

fn answer(request: &Value, auth: &str, p_of: &HashMap<(String, usize, String), f64>, line_no: &HashMap<(String, String), usize>, seen: &Mutex<Seen>) -> Value {
    let mut seen = seen.lock().unwrap();
    seen.requests += 1;
    if auth != format!("Bearer {FAKE_KEY}") {
        seen.bad_auth += 1;
    }
    let state = request["state"].as_object().unwrap();
    seen.state_keys.extend(state.keys().cloned());
    let file = state["file"].as_str().unwrap().to_string();
    let text = state["line"].as_str().unwrap().to_string();
    seen.files.insert(file.clone());
    let number = line_no.get(&(file.clone(), text)).copied().unwrap_or(0);
    let mut answers = serde_json::Map::new();
    for (name, question) in request["questions"].as_object().unwrap() {
        let Some(i) = name.strip_suffix("__private") else { continue };
        let instructions = question["instructions"].as_str().unwrap();
        let value = instructions.split('`').nth(1).unwrap().to_string();
        let p = match p_of.get(&(file.clone(), number, value.clone())) {
            Some(p) => *p,
            None => {
                seen.unknown.push(format!("{file}:{number} ({} chars)", value.chars().count()));
                0.0
            }
        };
        answers.insert(format!("{i}__private"), json!({"noul": p}));
        answers.insert(format!("{i}__kind"), json!({"choice": "other"}));
    }
    json!({"answers": answers})
}

fn scan(world: &World, url: Option<&str>, key: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_envscan"));
    command
        .current_dir(world.root.path())
        .args(["scan", "--env", "rules.env", "--json", "--full"])
        .args(FILES)
        .env("HOME", world.home.path())
        .env("TYPESAFE_API_KEY", key)
        .env_remove("ENVSCAN_JEV_ENDPOINT");
    if let Some(url) = url {
        command.env("ENVSCAN_JEV_ENDPOINT", url);
    }
    command.output().unwrap()
}

/// The overlap rule of the recorded run's scorer: same file and line, and one value contains
/// the other, case-insensitively.
fn overlap(a: &str, b: &str) -> bool {
    let (a, b) = (a.to_lowercase(), b.to_lowercase());
    a.contains(&b) || b.contains(&a)
}

#[derive(Debug, PartialEq)]
struct Score {
    flagged: usize,
    true_pos: usize,
    planted: usize,
    found: usize,
}

impl Score {
    fn precision(&self) -> f64 {
        self.true_pos as f64 / self.flagged as f64
    }
    fn recall(&self) -> f64 {
        self.found as f64 / self.planted as f64
    }
}

/// Every kept `(file, line, value)` in the report, scored against the planted values in `files`.
fn score(report: &Value, files: &[&str]) -> Score {
    let mut preds = Vec::new();
    for candidate in report["candidates"].as_array().unwrap() {
        if candidate.get("p").is_none() {
            continue;
        }
        let value = candidate["value"].as_str().unwrap();
        for at in candidate["at"].as_array().unwrap() {
            let (file, line) = at.as_str().unwrap().rsplit_once(':').unwrap();
            preds.push((file.to_string(), line.parse::<usize>().unwrap(), value.to_string()));
        }
    }
    let key: Vec<Value> =
        serde_json::from_str(&fs::read_to_string(fixtures().join("broad/answer-key.json")).unwrap()).unwrap();
    let planted: Vec<(String, usize, String)> = key
        .iter()
        .filter(|k| k["planted"] == true && files.contains(&k["file"].as_str().unwrap()))
        .map(|k| (k["file"].as_str().unwrap().to_string(), k["line"].as_u64().unwrap() as usize, expand(k["value"].as_str().unwrap())))
        .collect();
    let matches = |p: &(String, usize, String), k: &(String, usize, String)| p.0 == k.0 && p.1 == k.1 && overlap(&p.2, &k.2);
    Score {
        flagged: preds.len(),
        true_pos: preds.iter().filter(|p| planted.iter().any(|k| matches(p, k))).count(),
        planted: planted.len(),
        found: planted.iter().filter(|k| preds.iter().any(|p| matches(p, k))).count(),
    }
}

fn report(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stderr)))
}

fn eligible_files() -> Vec<&'static str> {
    FILES.iter().copied().filter(|f| envscan::judge::eligible_name(f)).collect()
}

#[test]
fn the_shipped_filter_replays_to_58_flagged_and_55_of_59() {
    let world = world("live");
    let (url, seen) = stub(&world);
    let out = scan(&world, Some(&url), FAKE_KEY);
    let report = report(&out);
    assert_eq!(report["tier"], "live (jev-1.14.0)", "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
    let seen = seen.lock().unwrap();
    assert!(seen.unknown.is_empty(), "values with no recorded p: {:?}", seen.unknown);
    assert_eq!(seen.bad_auth, 0);
    assert_eq!(seen.state_keys, HashSet::from(["file".to_string(), "line".to_string()]));
    // Every fixture file is an eligible type now, so all of them are sent.
    assert_eq!(eligible_files(), FILES);
    assert_eq!(seen.files, FILES.iter().map(|f| f.to_string()).collect::<HashSet<_>>());
    let all = score(&report, FILES);
    eprintln!("shipped filter: {all:?}");
    assert_eq!((all.flagged, all.planted, all.found), (58, 59, 55));
}

#[test]
fn a_stub_failure_discards_every_verdict() {
    let world = world("live");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}/v1/systemone", listener.local_addr().unwrap().port());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0; 65536];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n");
        }
    });
    let out = scan(&world, Some(&url), FAKE_KEY);
    let report = report(&out);
    assert_eq!(report["tier"], "plain (fallback from live: http 500)");
    assert_eq!(out.status.code(), Some(0));
    assert!(report.get("judgement").is_none());
    assert!(report["candidates"].as_array().unwrap().iter().all(|c| c.get("p").is_none()));
    assert!(report["candidates_total"].as_u64().unwrap() > 0);
}

#[test]
fn auto_and_plain_never_call() {
    for tier in ["auto", "plain"] {
        let world = world(tier);
        let (url, seen) = stub(&world);
        let out = scan(&world, Some(&url), FAKE_KEY);
        assert_eq!(report(&out)["tier"], "plain");
        assert_eq!(seen.lock().unwrap().requests, 0, "{tier}");
    }
}

#[test]
fn config_tier_saves_machine_wide_and_live_needs_a_private_key_file() {
    let world = world("plain");
    let saved = Command::new(env!("CARGO_BIN_EXE_envscan"))
        .args(["config", "tier", "live"])
        .env("HOME", world.home.path())
        .output()
        .unwrap();
    assert_eq!(saved.status.code(), Some(0));
    let config = fs::read_to_string(world.home.path().join(".config/envscan/config.toml")).unwrap();
    assert_eq!(config, "tier = \"live\"\n");

    // No key in the environment; the key file is readable by others, so it is refused.
    let key_file = world.home.path().join(".config/envscan/env");
    fs::write(&key_file, format!("TYPESAFE_API_KEY={FAKE_KEY}\n")).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&key_file, fs::Permissions::from_mode(0o644)).unwrap();
    let (url, seen) = stub(&world);
    let mut command = Command::new(env!("CARGO_BIN_EXE_envscan"));
    let out = command
        .current_dir(world.root.path())
        .args(["scan", "--env", "rules.env", "--json"])
        .args(FILES)
        .env("HOME", world.home.path())
        .env_remove("TYPESAFE_API_KEY")
        .env("ENVSCAN_JEV_ENDPOINT", &url)
        .output()
        .unwrap();
    assert_eq!(report(&out)["tier"], "plain (fallback from live: key file readable by others)");
    assert_eq!(seen.lock().unwrap().requests, 0);

    // Mode 0600: the file is parsed, never sourced, and the stub sees its key.
    fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
    let out = command.output().unwrap();
    assert_eq!(report(&out)["tier"], "live (jev-1.14.0)");
    let seen = seen.lock().unwrap();
    assert!(seen.requests > 0);
    assert_eq!(seen.bad_auth, 0);
}

#[test]
fn a_repo_env_is_never_read_for_the_key() {
    let world = world("live");
    fs::write(world.root.path().join("rules.env"), format!("UNRELATED=zqxunrelatedvalue\nTYPESAFE_API_KEY={FAKE_KEY}\n")).unwrap();
    let (url, seen) = stub(&world);
    let out = Command::new(env!("CARGO_BIN_EXE_envscan"))
        .current_dir(world.root.path())
        .args(["scan", "--env", "rules.env", "--json"])
        .args(FILES)
        .env("HOME", world.home.path())
        .env_remove("TYPESAFE_API_KEY")
        .env("ENVSCAN_JEV_ENDPOINT", &url)
        .output()
        .unwrap();
    assert_eq!(report(&out)["tier"], "plain (fallback from live: no key)");
    assert_eq!(seen.lock().unwrap().requests, 0);
}

/// Opt-in: the real vendor, the key from `~/.config/envscan/env` or the environment, the shipped
/// filter. Run with `cargo test --test judge -- --ignored --nocapture`. Costs under $0.01.
#[test]
#[ignore]
fn live_vendor_on_the_synthetic_fixture() {
    let key = envscan::config::api_key().expect("no vendor key on this machine");
    eprintln!("key: TYPESAFE_API_KEY, {} characters", key.chars().count());
    let world = world("live");
    let out = scan(&world, None, &key);
    let report = report(&out);
    eprintln!("tier: {}", report["tier"]);
    eprintln!("judgement: {}", report["judgement"]);
    assert_eq!(report["tier"], "live (jev-1.14.0)", "{}", String::from_utf8_lossy(&out.stderr));
    let all = score(&report, FILES);
    eprintln!(
        "{all:?} precision {:.3} recall {:.3}",
        all.precision(),
        all.recall()
    );
    assert!(all.precision() >= 0.90, "precision {:.3}", all.precision());
    assert!(all.recall() >= 0.93, "recall {:.3}", all.recall());
}
