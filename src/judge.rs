//! The vendor judgement call: requests per distinct flagged line, each carrying that line and its
//! relative path and nothing else. A long line's values split across requests. A request the
//! vendor refuses as too large marks only its line unjudged; any other failure discards every
//! verdict, so one report never mixes tiers. Which lines may be sent is decided by the caller,
//! `scan`.

use serde_json::{json, Map, Value};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

pub const MODEL: &str = "jev-1.14.0";
pub const THRESHOLD: f64 = 0.3;
pub const DEFAULT_MAX_CANDIDATES: usize = 25_000;
pub const DEFAULT_MAX_FILE_CANDIDATES: usize = 5_000;
const ENDPOINT: &str = "https://api.typesafe.ai/v1/systemone";
/// Lets a test point the binary at a local stub. Anything but loopback is refused, so it cannot
/// carry a line or the key off this machine.
const ENDPOINT_OVERRIDE: &str = "ENVSCAN_JEV_ENDPOINT";
/// Measured worst case: input tokens per value, whatever else is on the line.
const TOKENS_PER_VALUE: usize = 824;
const USD_PER_TOKEN: f64 = 0.042e-6;
/// Half the vendor's inferred overall cap of 66k tokens. Its measured edge was 173 values at
/// 65,685 tokens with only 5 of the 13 kinds; at 13 kinds and 824 tokens each the edge is about 80
/// values, and this budget stays well under it.
const REQUEST_TOKEN_BUDGET: usize = 33_000;
/// The vendor's `error_type` for a request over its limit.
const OVER_LIMIT: &str = "max_tokens_exceeded";
const THREADS: usize = 8;
const RETRIES: usize = 3;
const RETRY_AFTER_CAP_S: u64 = 30;

const EXTENSIONS: &[&str] = &["md", "txt", "py", "sh", "sql", "yml", "yaml", "toml", "log", "json", "diff"];

const KINDS: &[(&str, &str)] = &[
    ("client_or_company_name", "The name of a specific company, client, or organisation (not a software project or library)"),
    ("person_name", "A person's real name"),
    ("username_or_handle", "A login name or @handle of a specific person"),
    ("hostname_or_domain", "A server hostname or a domain name"),
    ("ip_address_or_range", "An IP address or IP range"),
    ("email_address", "An email address"),
    ("home_directory_path", "A file path inside a person's home directory"),
    ("storage_bucket", "A cloud storage bucket such as gs:// or s3://"),
    ("cloud_project_or_region", "A cloud project ID, region, or zone"),
    ("account_id", "A numeric cloud or billing account ID"),
    ("code_repository", "A source code repository name"),
    ("software_or_version", "A library, tool, package, image, or version number"),
    ("other", "Anything else"),
];
const NOUL_TRUE: &str = "The value points at one particular private organisation, person, machine, or account: for example a client company name, an internal or private hostname, a private IP address, a private repository, a private bucket, a cloud project or account ID, an individual's email, a username, or a path in someone's home directory. Publishing it would reveal who the work is for or where it runs.";
const NOUL_FALSE: &str = "The value is public or generic: a well-known public website or service, a public open-source project or its GitHub owner, a library or tool name, a version number, a loopback or public DNS address such as 127.0.0.1 or 8.8.8.8, a system path such as /var/log, or an ordinary word.";

/// May a file with this name be sent at all? Being named by the caller is checked separately.
pub fn eligible_name(name: &str) -> bool {
    std::path::Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
}

/// The line is repeated in each request. 0.4 tokens a byte upper-bounds every measurement: a 4 KB
/// line and 2 values models 3,286 against 2,508 measured, 87,280 bytes and 1 value 35,736 against
/// 32,983.
fn line_tokens(line_bytes: usize) -> usize {
    line_bytes * 2 / 5
}

/// How many values one request may ask about; a line longer than the budget still sends one.
pub fn values_per_request(line_bytes: usize) -> usize {
    (REQUEST_TOKEN_BUDGET.saturating_sub(line_tokens(line_bytes)) / TOKENS_PER_VALUE).max(1)
}

/// A worst case for these requests, so it is honest on long lines.
pub fn estimate_tokens(lines: &[Line]) -> usize {
    lines
        .iter()
        .map(|l| {
            let requests = l.values.len().div_ceil(values_per_request(l.text.len()));
            l.values.len() * TOKENS_PER_VALUE + requests * line_tokens(l.text.len())
        })
        .sum()
}

pub fn estimate_usd(lines: &[Line]) -> f64 {
    estimate_tokens(lines) as f64 * USD_PER_TOKEN
}

/// One request.
#[derive(Debug, Clone)]
pub struct Line {
    pub path: String,
    pub text: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub p: f64,
    pub kind: String,
}

pub fn request_body(line: &Line) -> Value {
    let mut questions = Map::new();
    let kinds: Map<String, Value> = KINDS.iter().map(|(k, v)| (k.to_string(), json!(v))).collect();
    for (i, value) in line.values.iter().enumerate() {
        questions.insert(format!("c{i}__private"), json!({
            "type": "noul",
            "instructions": format!("Is the value `{value}` in `line` a private identifier that should be moved into a local .env file before this text is published?"),
            "criteria": {"true": NOUL_TRUE, "false": NOUL_FALSE},
        }));
        questions.insert(format!("c{i}__kind"), json!({
            "type": "choice",
            "instructions": format!("What kind of value is `{value}` in `line`?"),
            "criteria": kinds,
        }));
    }
    json!({"model": MODEL, "state": {"file": line.path, "line": line.text}, "questions": questions})
}

/// A missing answer or an out-of-range p fails the run, never reads as "not private".
pub fn parse_answers(response: &Value, count: usize) -> Result<Vec<Verdict>, String> {
    let answers = response.get("answers").ok_or("bad response")?;
    (0..count)
        .map(|i| {
            let p = answers[format!("c{i}__private")]["noul"].as_f64().ok_or("bad response")?;
            if !p.is_finite() || !(0.0..=1.0).contains(&p) {
                return Err("bad response".to_string());
            }
            let kind = answers[format!("c{i}__kind")]["choice"].as_str().ok_or("bad response")?;
            Ok(Verdict { p, kind: kind.to_string() })
        })
        .collect()
}

pub struct Client {
    agent: ureq::Agent,
    url: String,
    bearer: String,
}

impl Client {
    /// The vendor, unless a loopback override is set. The error is a fixed reason.
    pub fn from_env(key: &str) -> Result<Client, String> {
        match std::env::var(ENDPOINT_OVERRIDE) {
            Ok(url) if is_loopback(&url) => Ok(Client::new(&url, key, true)),
            Ok(_) => Err("endpoint override is not loopback".to_string()),
            Err(_) => Ok(Client::new(ENDPOINT, key, false)),
        }
    }

    /// For the library's tests and the opt-in live run.
    pub fn new(url: &str, key: &str, loopback: bool) -> Client {
        let proxy = if loopback { None } else { ureq::Proxy::try_from_env() };
        let agent = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(5)))
            .timeout_global(Some(Duration::from_secs(30)))
            .http_status_as_error(false)
            // A redirect would carry the line, and could carry the key, somewhere unchosen.
            .max_redirects(0)
            .proxy(proxy)
            .build()
            .into();
        Client { agent, url: url.to_string(), bearer: format!("Bearer {key}") }
    }

    fn call(&self, body: &str) -> Result<Value, String> {
        let mut reason = String::new();
        for attempt in 0..=RETRIES {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(500 << (attempt - 1)));
            }
            let sent = self
                .agent
                .post(&self.url)
                .header("Authorization", &self.bearer)
                .header("Content-Type", "application/json")
                .send(body);
            let mut response = match sent {
                Ok(response) => response,
                // Fixed text: a transport error can quote the request.
                Err(_) => {
                    reason = "network".to_string();
                    continue;
                }
            };
            let status = response.status().as_u16();
            if status == 429 || status == 529 {
                reason = format!("http {status}");
                let wait = response.headers().get("retry-after").and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
                if let (Some(wait), true) = (wait, attempt < RETRIES) {
                    std::thread::sleep(Duration::from_secs(wait.min(RETRY_AFTER_CAP_S)));
                }
                continue;
            }
            if status == 400 {
                let text = response.body_mut().read_to_string().unwrap_or_default();
                let body: Value = serde_json::from_str(&text).unwrap_or_default();
                // Not retried: the same request would be refused again.
                let over = body["detail"]["error_type"] == OVER_LIMIT;
                return Err(if over { OVER_LIMIT.to_string() } else { "http 400".to_string() });
            }
            if status != 200 {
                return Err(format!("http {status}"));
            }
            return match response.body_mut().read_to_string() {
                Ok(text) => serde_json::from_str(&text).map_err(|_| "bad response".to_string()),
                Err(_) => {
                    reason = "network".to_string();
                    continue;
                }
            };
        }
        Err(reason)
    }
}

fn is_loopback(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else { return false };
    let authority = rest.split('/').next().unwrap_or("");
    let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
    host == "127.0.0.1" || host == "localhost"
}

/// Verdicts per line, in order and per value, or the first failure's reason. `None` is a line the
/// vendor refused as over its limit, in any of that line's requests.
pub fn judge(client: &Client, lines: &[Line]) -> Result<Vec<Option<Vec<Verdict>>>, String> {
    // Each request repeats the whole line with its own values, so `c0` restarts per request.
    let batches: Vec<(usize, Line)> = lines
        .iter()
        .enumerate()
        .flat_map(|(i, line)| {
            line.values.chunks(values_per_request(line.text.len())).map(move |values| {
                (i, Line { path: line.path.clone(), text: line.text.clone(), values: values.to_vec() })
            })
        })
        .collect();
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let failure = Mutex::new(None::<String>);
    let results = Mutex::new(vec![None::<Vec<Verdict>>; batches.len()]);
    std::thread::scope(|scope| {
        for _ in 0..THREADS.min(batches.len()) {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::SeqCst);
                if i >= batches.len() || failed.load(Ordering::SeqCst) {
                    return;
                }
                let batch = &batches[i].1;
                let body = request_body(batch).to_string();
                let verdicts = client.call(&body).and_then(|r| parse_answers(&r, batch.values.len()));
                match verdicts {
                    Ok(verdicts) => results.lock().unwrap()[i] = Some(verdicts),
                    Err(reason) if reason == OVER_LIMIT => {}
                    Err(reason) => {
                        failed.store(true, Ordering::SeqCst);
                        failure.lock().unwrap().get_or_insert(reason);
                        return;
                    }
                }
            });
        }
    });
    match failure.into_inner().unwrap() {
        Some(reason) => Err(reason),
        None => {
            let mut merged = vec![Some(Vec::new()); lines.len()];
            for ((i, _), result) in batches.iter().zip(results.into_inner().unwrap()) {
                match (result, &mut merged[*i]) {
                    (Some(verdicts), Some(line)) => line.extend(verdicts),
                    (None, slot) => *slot = None,
                    (Some(_), None) => {}
                }
            }
            Ok(merged)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_listed_extensions_are_eligible() {
        for name in ["a.md", "a.TXT", "b.py", "c.sh", "d.sql", "e.yml", "f.yaml", "g.toml", "a.log", "a.json", "a.diff"] {
            assert!(eligible_name(name), "{name}");
        }
        for name in ["a.csv", "a", "a.md.bak", ".env", "Dockerfile", ".env.example"] {
            assert!(!eligible_name(name), "{name}");
        }
    }

    #[test]
    fn a_long_line_splits_and_a_short_one_nearly_fills_the_budget() {
        assert_eq!(values_per_request(4090), 38);
        assert_eq!(values_per_request(40), 40);
        assert_eq!(values_per_request(1_000_000), 1);
    }

    #[test]
    fn the_estimate_is_a_worst_case_on_a_long_line() {
        let line = Line { path: "a.md".into(), text: "x".repeat(4096), values: vec!["a".into(), "b".into()] };
        assert!(estimate_tokens(std::slice::from_ref(&line)) >= 2508);
        assert!(estimate_usd(&[line]) > 0.0);
    }

    #[test]
    fn loopback_means_the_host_not_a_prefix() {
        assert!(is_loopback("http://127.0.0.1:9/v"));
        assert!(!is_loopback("https://127.0.0.1:9/v"));
        assert!(!is_loopback("http://127.0.0.1.elsewhere.invalid/v"));
    }

    #[test]
    fn the_request_holds_line_and_path_only() {
        let line = Line { path: "a.md".into(), text: "host zq.lan".into(), values: vec!["zq.lan".into()] };
        let body = request_body(&line);
        let state: Vec<&String> = body["state"].as_object().unwrap().keys().collect();
        assert_eq!(state, ["file", "line"]);
        assert_eq!(body["model"], MODEL);
        assert_eq!(body["questions"].as_object().unwrap().len(), 2);
    }

    #[test]
    fn exactly_the_threshold_is_not_kept_by_callers() {
        assert!(!(0.3_f64 > THRESHOLD));
    }

    #[test]
    fn a_missing_or_impossible_answer_fails() {
        let good = json!({"answers": {"c0__private": {"noul": 0.4}, "c0__kind": {"choice": "other"}}});
        assert_eq!(parse_answers(&good, 1).unwrap()[0].p, 0.4);
        assert!(parse_answers(&good, 2).is_err());
        let wild = json!({"answers": {"c0__private": {"noul": 1.4}, "c0__kind": {"choice": "other"}}});
        assert!(parse_answers(&wild, 1).is_err());
    }
}
