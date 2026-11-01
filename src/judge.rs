//! The vendor judgement call: one request per distinct flagged line, carrying that line and its
//! relative path and nothing else. All or nothing: any failure discards every verdict, so one
//! report never mixes tiers. Which lines may be sent is decided by the caller, `scan`.

use serde_json::{json, Map, Value};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

pub const MODEL: &str = "jev-1.14.0";
pub const THRESHOLD: f64 = 0.3;
pub const DEFAULT_MAX_CANDIDATES: usize = 5000;
const ENDPOINT: &str = "https://api.typesafe.ai/v1/systemone";
/// Lets a test point the binary at a local stub. Anything but loopback is refused, so it cannot
/// carry a line or the key off this machine.
const ENDPOINT_OVERRIDE: &str = "ENVSCAN_JEV_ENDPOINT";
/// Measured worst case: 824 input tokens per candidate at $0.042 per million.
const USD_PER_CANDIDATE: f64 = 0.0000346;
const THREADS: usize = 8;
const RETRIES: usize = 3;
const RETRY_AFTER_CAP_S: u64 = 30;

const EXTENSIONS: &[&str] = &["md", "txt", "py", "sh", "sql", "yml", "yaml", "toml"];

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

/// For the replay test only: every extension is eligible, so recorded verdicts for the whole
/// fixture can be replayed. Honoured only beside a loopback endpoint override, so it can never
/// widen what reaches the vendor. Not a flag, and not documented for callers.
const STUB_ALL_EXTENSIONS: &str = "ENVSCAN_JEV_STUB_ALL_EXTENSIONS";

/// Whether the replay test has widened eligibility to every extension.
pub fn stub_widens() -> bool {
    std::env::var(STUB_ALL_EXTENSIONS).is_ok_and(|v| v == "1")
        && std::env::var(ENDPOINT_OVERRIDE).is_ok_and(|url| is_loopback(&url))
}

/// May a file with this name be sent at all? Being named by the caller is checked separately.
pub fn eligible_name(name: &str) -> bool {
    std::path::Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
}

pub fn estimate_usd(candidates: usize) -> f64 {
    candidates as f64 * USD_PER_CANDIDATE
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

/// Verdicts per line, in order and per value, or the first failure's reason.
pub fn judge(client: &Client, lines: &[Line]) -> Result<Vec<Vec<Verdict>>, String> {
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let failure = Mutex::new(None::<String>);
    let results = Mutex::new(vec![Vec::new(); lines.len()]);
    std::thread::scope(|scope| {
        for _ in 0..THREADS.min(lines.len()) {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::SeqCst);
                if i >= lines.len() || failed.load(Ordering::SeqCst) {
                    return;
                }
                let body = request_body(&lines[i]).to_string();
                let verdicts = client.call(&body).and_then(|r| parse_answers(&r, lines[i].values.len()));
                match verdicts {
                    Ok(verdicts) => results.lock().unwrap()[i] = verdicts,
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
        None => Ok(results.into_inner().unwrap()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_listed_extensions_are_eligible() {
        for name in ["a.md", "a.TXT", "b.py", "c.sh", "d.sql", "e.yml", "f.yaml", "g.toml"] {
            assert!(eligible_name(name), "{name}");
        }
        for name in ["a.json", "a.log", "a.csv", "a", "a.md.bak", ".env"] {
            assert!(!eligible_name(name), "{name}");
        }
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
