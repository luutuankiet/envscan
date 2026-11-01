//! The promotion record: which `tmp/` files were handled, how, and whether a topic folder
//! can be cleared. An append-only file outside any repo, so a moved clone keeps its record.
//! Every doubt resolves to "not safe": a record that cannot be read is no record.

use crate::exit::Exit;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const HANDLINGS: [&str; 5] = ["snapshot", "write-up", "cache", "discard", "refuse"];
/// Tried in order; full ref names, so a tag or a path called `main` cannot stand in.
const DEFAULT_BRANCHES: [(&str, &str); 3] = [
    ("origin/HEAD", "refs/remotes/origin/HEAD"),
    ("main", "refs/heads/main"),
    ("master", "refs/heads/master"),
];

#[derive(Args, Debug)]
pub struct PromotionArgs {
    #[command(subcommand)]
    pub command: PromotionCommand,
}

#[derive(Subcommand, Debug)]
pub enum PromotionCommand {
    /// Record how one file was handled. Exit 0 recorded, 2 the repo has no commits or is
    /// shallow, 3 usage or IO error or the file's digest differs, which sends it to the menu.
    Add(AddArgs),
    /// Report each file's state and whether the folder is safe to clear. Exit 0 with the
    /// verdict in `safe_to_clear`, whichever way it went; 3 usage or IO error.
    Status(StatusArgs),
}

#[derive(Args, Debug)]
pub struct AddArgs {
    pub file: PathBuf,
    /// The digest shown on the menu.
    #[arg(long, value_name = "DIGEST")]
    pub sha256: String,
    #[arg(long, value_parser = clap::builder::PossibleValuesParser::new(HANDLINGS))]
    pub handling: String,
    /// A full commit SHA for snapshot and cache; a full SHA or `issue:<n>` for write-up;
    /// absent for discard and refuse.
    #[arg(long = "ref", value_name = "REF")]
    pub reference: Option<String>,
}

#[derive(Args, Debug)]
pub struct StatusArgs {
    pub folder: PathBuf,
    /// Print the report as JSON.
    #[arg(long)]
    pub json: bool,
}

/// Field order is the on-disk contract.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct Record {
    v: u32,
    repo: String,
    path: String,
    sha256: String,
    handling: String,
    at: String,
    #[serde(rename = "ref")]
    reference: Option<String>,
}

impl Record {
    fn is_valid(&self) -> bool {
        self.v == 1
            && is_hex(&self.repo, 40)
            && !self.path.is_empty()
            && is_hex(&self.sha256, 64)
            && check_ref(&self.handling, self.reference.as_deref()).is_ok()
    }
}

#[derive(Serialize, Debug)]
struct Item {
    path: String,
    sha256: Option<String>,
    state: &'static str,
    handling: Option<String>,
    #[serde(rename = "ref")]
    reference: Option<String>,
    ref_ok: bool,
}

#[derive(Serialize, Debug)]
struct Status {
    files: Vec<Item>,
    safe_to_clear: bool,
    reasons: Vec<String>,
    refused_deleted_on_clear: Vec<String>,
    skipped_lines: usize,
}

pub fn run(args: &PromotionArgs) -> Exit {
    match &args.command {
        PromotionCommand::Add(add_args) => add(add_args),
        PromotionCommand::Status(status_args) => status(status_args),
    }
}

/// Lowercase only, because the digest and the SHAs are compared as text.
fn is_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_issue(reference: &str) -> bool {
    reference.strip_prefix("issue:").is_some_and(|n| {
        !n.is_empty() && !n.starts_with('0') && n.bytes().all(|b| b.is_ascii_digit())
    })
}

fn check_ref(handling: &str, reference: Option<&str>) -> Result<(), String> {
    match (handling, reference) {
        ("snapshot" | "cache", Some(r)) if is_hex(r, 40) => Ok(()),
        ("snapshot" | "cache", _) => Err(format!("{handling} takes --ref with a full commit SHA")),
        ("write-up", Some(r)) if is_hex(r, 40) || is_issue(r) => Ok(()),
        ("write-up", _) => Err("write-up takes --ref with a full commit SHA or issue:<n>".into()),
        ("discard" | "refuse", None) => Ok(()),
        ("discard" | "refuse", Some(_)) => Err(format!("{handling} takes no --ref")),
        _ => Err(format!("unknown handling {handling}")),
    }
}

fn store_path() -> Result<PathBuf, String> {
    match std::env::var_os("HOME") {
        Some(home) if !home.is_empty() => Ok(PathBuf::from(home).join(".local/state/envscan/promotions.jsonl")),
        _ => Err("HOME is not set, so the record has no location".into()),
    }
}

/// The leading newline keeps a torn line from an earlier crash from swallowing this one, and
/// one `O_APPEND` write keeps concurrent writers from interleaving.
fn append(store: &Path, record: &Record) -> io::Result<()> {
    let dir = store.parent().expect("the store path has a parent");
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent)?;
    }
    match DirBuilder::new().mode(0o700).create(dir) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
        _ => {}
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    let mut file = OpenOptions::new().append(true).create(true).mode(0o600).open(store)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    let json = serde_json::to_string(record).map_err(io::Error::other)?;
    let line = format!("\n{json}\n");
    let written = file.write(line.as_bytes())?;
    if written != line.len() {
        return Err(io::Error::other("short write; the line is torn and will be skipped"));
    }
    Ok(())
}

/// Every valid record in file order, and how many non-blank lines were not valid. A missing
/// store is an empty one.
fn read_store(store: &Path) -> io::Result<(Vec<Record>, usize)> {
    let bytes = match fs::read(store) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
        Err(e) => return Err(e),
    };
    let mut records = Vec::new();
    let mut skipped = 0;
    for line in bytes.split(|b| *b == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match serde_json::from_slice::<Record>(line) {
            Ok(record) if record.is_valid() => records.push(record),
            _ => skipped += 1,
        }
    }
    Ok((records, skipped))
}

/// `GIT_DIR` and friends, set when run from a hook, would answer for some other repo.
fn git_command(dir: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("git");
    command
        .args(args)
        .current_dir(dir)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_INDEX_FILE")
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = git_command(dir, args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8(out.stdout).ok()?.trim_end().to_string())
}

struct Repo {
    /// The work tree's top, when there is a work tree. Paths in the record are relative to it.
    top: Option<PathBuf>,
    /// The root commit that names this repo, or why there is none to trust.
    id: Result<String, String>,
}

fn locate(dir: &Path) -> Repo {
    let top = git(dir, &["rev-parse", "--show-toplevel"]).and_then(|t| PathBuf::from(t).canonicalize().ok());
    let id = if top.is_none() {
        Err("not in a git repository".to_string())
    } else if git(dir, &["rev-parse", "--is-shallow-repository"]).as_deref() == Some("true") {
        Err("a shallow clone has a different root commit from a full one, so it cannot name the repo".to_string())
    } else {
        match git(dir, &["rev-list", "--max-parents=0", "HEAD"]) {
            Some(roots) => match roots.lines().min() {
                Some(first) if is_hex(first, 40) => Ok(first.to_string()),
                Some(_) => Err("the root commit is not a 40 hex SHA".to_string()),
                None => Err("the repo has no commits".to_string()),
            },
            None => Err("the repo has no commits".to_string()),
        }
    };
    Repo { top, id }
}

fn hash_file(path: &Path) -> io::Result<String> {
    let mut hasher = Sha256::new();
    io::copy(&mut File::open(path)?, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn add(args: &AddArgs) -> Exit {
    match try_add(args) {
        Ok(path) => {
            println!("recorded {path} as {}", args.handling);
            Exit::Clean
        }
        Err((exit, message)) => {
            eprintln!("envscan: promotion add: {message}");
            exit
        }
    }
}

fn try_add(args: &AddArgs) -> Result<String, (Exit, String)> {
    let usage = |message: String| (Exit::Error, message);
    let shown = args.file.display();
    if !is_hex(&args.sha256, 64) {
        return Err(usage("--sha256 takes 64 lowercase hex characters".into()));
    }
    check_ref(&args.handling, args.reference.as_deref()).map_err(usage)?;
    let meta = fs::symlink_metadata(&args.file).map_err(|e| usage(format!("{shown}: {e}")))?;
    if !meta.is_file() {
        return Err(usage(format!("{shown}: not a regular file, and status lists only those")));
    }
    let actual = hash_file(&args.file).map_err(|e| usage(format!("{shown}: {e}")))?;
    if actual != args.sha256 {
        return Err(usage(format!("{shown}: changed since the menu, so it goes back to the menu")));
    }
    let name = args.file.file_name().ok_or_else(|| usage(format!("{shown}: no file name")))?;
    let parent = match args.file.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let parent = parent.canonicalize().map_err(|e| usage(format!("{shown}: {e}")))?;
    let repo = locate(&parent);
    let id = repo.id.map_err(|why| (Exit::NoRules, format!("nothing recorded: {why}")))?;
    let top = repo.top.expect("a repo id implies a work tree");
    let relative = parent.join(name);
    let relative = relative
        .strip_prefix(&top)
        .map_err(|_| usage(format!("{shown}: outside the work tree")))?
        .to_str()
        .ok_or_else(|| usage(format!("{shown}: the path is not UTF-8")))?
        .to_string();
    let record = Record {
        v: 1,
        repo: id,
        path: relative.clone(),
        sha256: actual,
        handling: args.handling.clone(),
        at: utc_now(),
        reference: args.reference.clone(),
    };
    let store = store_path().map_err(usage)?;
    append(&store, &record).map_err(|e| usage(format!("{}: {e}", store.display())))?;
    Ok(relative)
}

fn holds_git(dir: &Path) -> bool {
    fs::symlink_metadata(dir.join(".git")).is_ok()
}

enum Found {
    File { path: PathBuf, relative: String },
    Clone { relative: String },
    /// A path that could not be listed.
    Unlistable { relative: String, error: io::Error },
}

/// Every regular file, in name order. Ignore rules do not apply and symlinks are not
/// followed. A directory holding `.git` is one item, not a tree to enter.
fn enumerate(dir: &Path, relative: &str, found: &mut Vec<Found>) {
    let entries = match fs::read_dir(dir).and_then(|it| it.collect::<io::Result<Vec<_>>>()) {
        Ok(entries) => entries,
        Err(error) => {
            found.push(Found::Unlistable { relative: relative.to_string(), error });
            return;
        }
    };
    let mut entries = entries;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let child = if relative.is_empty() { name.to_string() } else { format!("{relative}/{name}") };
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => {
                if holds_git(&path) {
                    found.push(Found::Clone { relative: child });
                } else {
                    enumerate(&path, &child, found);
                }
            }
            Ok(kind) if kind.is_file() => found.push(Found::File { path, relative: child }),
            Ok(_) => {}
            Err(error) => found.push(Found::Unlistable { relative: child, error }),
        }
    }
}

/// Answers "is this commit on the default branch?", asking git once per SHA.
struct Ancestry<'a> {
    dir: &'a Path,
    /// Resolved on first use, since a folder of only discards and issues needs no branch.
    target: Option<Option<(&'static str, &'static str)>>,
    known: HashMap<String, bool>,
    reasons: Vec<String>,
}

impl Ancestry<'_> {
    fn landed(&mut self, sha: &str) -> bool {
        if let Some(known) = self.known.get(sha) {
            return *known;
        }
        let dir = self.dir;
        let target = *self.target.get_or_insert_with(|| {
            DEFAULT_BRANCHES.into_iter().find(|(_, full)| {
                git(dir, &["rev-parse", "--verify", "--quiet", &format!("{full}^{{commit}}")]).is_some()
            })
        });
        let landed = match target {
            None => {
                if self.known.is_empty() {
                    self.reasons.push("no origin/HEAD, main or master to check commits against".to_string());
                }
                false
            }
            Some((name, full)) => {
                let yes = git_command(dir, &["merge-base", "--is-ancestor", sha, full])
                    .stdout(Stdio::null())
                    .status()
                    .is_ok_and(|s| s.success());
                if !yes {
                    self.reasons.push(format!(
                        "{sha} is not an ancestor of {name}: not merged yet, or squash merged, which only a delete by hand can override"
                    ));
                }
                yes
            }
        };
        self.known.insert(sha.to_string(), landed);
        landed
    }
}

fn status(args: &StatusArgs) -> Exit {
    let root = match args.folder.canonicalize() {
        Ok(root) if root.is_dir() => root,
        Ok(_) => {
            eprintln!("envscan: promotion status: {}: not a directory", args.folder.display());
            return Exit::Error;
        }
        Err(e) => {
            eprintln!("envscan: promotion status: {}: {e}", args.folder.display());
            return Exit::Error;
        }
    };
    let store = match store_path() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("envscan: promotion status: {e}");
            return Exit::Error;
        }
    };
    let (records, skipped_lines) = match read_store(&store) {
        Ok(read) => read,
        Err(e) => {
            eprintln!("envscan: promotion status: {}: {e}", store.display());
            return Exit::Error;
        }
    };
    let (report, unreadable) = build_status(&root, &args.folder, records, skipped_lines);
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report).expect("the status is plain data"));
    } else {
        print!("{}", status_text(&report));
    }
    if unreadable > 0 {
        Exit::Error
    } else {
        Exit::Clean
    }
}

fn build_status(root: &Path, given: &Path, records: Vec<Record>, skipped_lines: usize) -> (Status, usize) {
    // A folder that is itself a clone answers git questions for that clone, not this repo.
    let root_is_clone = holds_git(root);
    let ask_from = if root_is_clone { root.parent().unwrap_or(root) } else { root };
    let repo = locate(ask_from);
    let prefix = match &repo.top {
        Some(top) => root.strip_prefix(top).map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
        None => given.to_string_lossy().trim_end_matches('/').to_string(),
    };
    let join = |relative: &str| match (prefix.is_empty(), relative.is_empty()) {
        (true, true) => ".".to_string(),
        (true, false) => relative.to_string(),
        (false, true) => prefix.clone(),
        (false, false) => format!("{prefix}/{relative}"),
    };

    let mut latest: HashMap<String, Record> = HashMap::new();
    if let Ok(id) = &repo.id {
        for record in records.into_iter().filter(|r| &r.repo == id) {
            latest.insert(record.path.clone(), record);
        }
    }

    let mut found = Vec::new();
    if root_is_clone {
        found.push(Found::Clone { relative: String::new() });
    } else {
        enumerate(root, "", &mut found);
    }

    let mut reasons = Vec::new();
    if let Err(why) = &repo.id {
        reasons.push(why.clone());
    }
    if found.is_empty() {
        reasons.push("the folder holds no regular files".to_string());
    }
    let mut ancestry = Ancestry { dir: ask_from, target: None, known: HashMap::new(), reasons: Vec::new() };
    let mut files = Vec::new();
    let mut unreadable = 0;
    let (mut none_count, mut changed_count) = (0, 0);
    for entry in found {
        let (path, relative) = match entry {
            Found::File { path, relative } => (path, relative),
            Found::Clone { relative } => {
                let path = join(&relative);
                reasons.push(format!("{path} holds .git: move to tmp/refs/"));
                files.push(none_item(path, None));
                continue;
            }
            Found::Unlistable { relative, error } => {
                let path = join(&relative);
                reasons.push(format!("{path} cannot be listed: {error}"));
                unreadable += 1;
                files.push(none_item(path, None));
                continue;
            }
        };
        let shown = join(&relative);
        let sha256 = match hash_file(&path) {
            Ok(sha) => sha,
            Err(error) => {
                reasons.push(format!("{shown} cannot be read: {error}"));
                unreadable += 1;
                files.push(none_item(shown, None));
                continue;
            }
        };
        // A lossy name is not the file's name, so it can match no record.
        let record = path.to_str().and_then(|_| latest.get(&shown));
        let Some(record) = record else {
            none_count += 1;
            files.push(none_item(shown, Some(sha256)));
            continue;
        };
        let state = if record.sha256 == sha256 { "recorded" } else { "changed" };
        if state == "changed" {
            changed_count += 1;
        }
        let ref_ok = match record.reference.as_deref() {
            Some(r) if is_hex(r, 40) => ancestry.landed(r),
            _ => true, // `issue:<n>` counts as done, and discard and refuse have nothing to land.
        };
        files.push(Item {
            path: shown,
            sha256: Some(sha256),
            state,
            handling: Some(record.handling.clone()),
            reference: record.reference.clone(),
            ref_ok,
        });
    }
    if none_count > 0 {
        reasons.push(format!("{none_count} file(s) have no record"));
    }
    if changed_count > 0 {
        reasons.push(format!("{changed_count} file(s) changed since their record"));
    }
    reasons.append(&mut ancestry.reasons);
    let refused_deleted_on_clear =
        files.iter().filter(|f| f.handling.as_deref() == Some("refuse")).map(|f| f.path.clone()).collect();
    let report = Status { files, safe_to_clear: reasons.is_empty(), reasons, refused_deleted_on_clear, skipped_lines };
    (report, unreadable)
}

fn none_item(path: String, sha256: Option<String>) -> Item {
    Item { path, sha256, state: "none", handling: None, reference: None, ref_ok: false }
}

fn status_text(report: &Status) -> String {
    let mut out = String::new();
    for f in &report.files {
        out.push_str(&format!(
            "{:<9} {:<9} {:<46} ref_ok {:<5} {}\n",
            f.state,
            f.handling.as_deref().unwrap_or("-"),
            f.reference.as_deref().unwrap_or("-"),
            f.ref_ok,
            f.path
        ));
    }
    out.push_str(&format!("safe_to_clear: {}\n", report.safe_to_clear));
    for reason in &report.reasons {
        out.push_str(&format!("reason: {reason}\n"));
    }
    for path in &report.refused_deleted_on_clear {
        out.push_str(&format!("refused, deleted on clear: {path}\n"));
    }
    if report.skipped_lines > 0 {
        out.push_str(&format!("record lines skipped: {}\n", report.skipped_lines));
    }
    out
}

fn utc_now() -> String {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    utc_timestamp(seconds)
}

/// Days to a calendar date by the standard civil-from-days method, to avoid a date crate for
/// one format.
fn utc_timestamp(seconds: u64) -> String {
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", rest / 3_600, rest % 3_600 / 60, rest % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_cross_leap_days_and_year_ends() {
        assert_eq!(utc_timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_timestamp(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(utc_timestamp(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(utc_timestamp(1_735_689_599), "2024-12-31T23:59:59Z");
        assert_eq!(utc_timestamp(1_793_534_400), "2026-11-01T12:00:00Z");
    }

    #[test]
    fn refs_follow_the_handling() {
        let sha = "a".repeat(40);
        assert!(check_ref("snapshot", Some(&sha)).is_ok());
        assert!(check_ref("cache", Some(&sha)).is_ok());
        assert!(check_ref("write-up", Some(&sha)).is_ok());
        assert!(check_ref("write-up", Some("issue:72")).is_ok());
        assert!(check_ref("discard", None).is_ok());
        assert!(check_ref("refuse", None).is_ok());

        assert!(check_ref("snapshot", None).is_err());
        assert!(check_ref("snapshot", Some("issue:72")).is_err());
        assert!(check_ref("cache", Some(&sha[..7])).is_err());
        assert!(check_ref("cache", Some(&"A".repeat(40))).is_err());
        assert!(check_ref("write-up", None).is_err());
        assert!(check_ref("write-up", Some("issue:")).is_err());
        assert!(check_ref("write-up", Some("issue:0")).is_err());
        assert!(check_ref("write-up", Some("issue:7x")).is_err());
        assert!(check_ref("write-up", Some("https://example.invalid/1")).is_err());
        assert!(check_ref("discard", Some(&sha)).is_err());
        assert!(check_ref("refuse", Some("issue:1")).is_err());
    }
}
