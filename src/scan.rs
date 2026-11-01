//! `envscan scan`: load rules, walk, match, report, choose the exit code.

use crate::cli::ScanArgs;
use crate::data::{self, RuleHits, Streamed};
use crate::env::{self, EnvFile};
use crate::config::{self, Saved};
use crate::exit::Exit;
use crate::extract::{self, Found};
use crate::judge;
use crate::matcher::{Hit, Matcher};
use crate::report::{Candidate, DataFile, Judgement, Leak, Report, Skipped};
use crate::walker::{self, Options};
use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MAX_FILE_BYTES: u64 = 2_000_000;
const SNIFF_BYTES: usize = 8192;
/// Locations listed per key; `--full` lists every one.
const AT_CAP: usize = 3;
const STDIN_LABEL: &str = "<stdin>";

pub fn run(args: &ScanArgs) -> Exit {
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(e) => return fail(&format!("cannot read the working directory: {e}")),
    };

    let env_path = env::discover(args.env.as_deref(), &cwd);
    let env_file = match &env_path {
        Some(path) => match EnvFile::load(path) {
            Ok(file) => file,
            Err(e) => return fail(&format!("cannot read the env file: {e}")),
        },
        None => EnvFile::default(),
    };
    let matcher = match Matcher::new(env_file.rules()) {
        Ok(matcher) => matcher,
        Err(e) => return fail(&format!("cannot build the rules: {e}")),
    };

    let mut roots = args.paths.clone();
    if roots.is_empty() && !args.stdin {
        roots.push(PathBuf::from("."));
    }
    // Before any work: a missing path must never read as clean, whatever else is found.
    let missing: Vec<&PathBuf> = roots.iter().filter(|p| !cwd.join(p).exists()).collect();
    if !missing.is_empty() {
        for path in missing {
            eprintln!("envscan: missing path: {}", matcher.redact(&path.display().to_string()));
        }
        return Exit::Error;
    }

    let mut scan = Scan::new(&matcher, args.full);
    if args.stdin {
        let mut bytes = Vec::new();
        if let Err(e) = std::io::stdin().read_to_end(&mut bytes) {
            return fail(&format!("cannot read stdin: {e}"));
        }
        let outcome = scan_bytes(&matcher, &bytes, !args.known_only, false);
        scan.absorb(STDIN_LABEL, outcome);
    }

    let walked = walker::walk(
        &roots,
        &cwd,
        &Options { no_ignore: args.no_ignore, rules_file: args.env.as_ref().map(|p| cwd.join(p)) },
    );
    scan.skipped.secret_named = walked.secret_named;
    scan.errors.extend(walked.errors.iter().map(|e| matcher.redact(e)));

    // Only a path on the command line is named by the caller; a walked directory's files are not.
    let tier = Tier::choose(args);
    let named: HashSet<PathBuf> = match tier {
        Tier::Live { .. } => roots.iter().filter_map(|r| cwd.join(r).canonicalize().ok()).collect(),
        _ => HashSet::new(),
    };
    let any_extension = judge::stub_widens();

    // Sorted input and an order-keeping collect keep the report deterministic.
    let outcomes: Vec<(Vec<Hit>, Option<Outcome>)> = walked
        .items
        .par_iter()
        .map(|item| {
            let name_hits = matcher.find(item.name.as_bytes());
            let outcome = item.is_file.then(|| match extract::data_format(&item.name) {
                Some(format) => scan_data_file(&matcher, &item.path, format, args.full),
                None => {
                    let sendable = named.contains(&item.path) && (any_extension || judge::eligible_name(&item.name));
                    scan_file(&matcher, &item.path, !args.known_only, sendable)
                }
            });
            (name_hits, outcome)
        })
        .collect();
    for (item, (name_hits, outcome)) in walked.items.iter().zip(outcomes) {
        scan.absorb_name(&item.display, &name_hits);
        if let Some(outcome) = outcome {
            scan.absorb(&item.display, outcome);
        }
    }

    let tier = tier.run(&mut scan, args);
    let example = env::example_for(env_path.as_deref(), &cwd);
    let warn = example.and_then(|p| env::Example::load(&p).ok()).unwrap_or_default().warn;
    finish(scan, &env_file, args, tier, &warn)
}

/// What the report will say, decided before any file is read so a bad setup sends nothing.
enum Tier {
    Plain,
    Live { key: String },
    Fallback(String),
}

impl Tier {
    fn choose(args: &ScanArgs) -> Tier {
        if args.known_only {
            return Tier::Plain;
        }
        match config::saved_tier() {
            Saved::Plain => Tier::Plain,
            Saved::Unset => {
                eprintln!("envscan: judgement is off; `envscan config tier live` or `plain` settles it");
                Tier::Plain
            }
            Saved::Bad => {
                eprintln!("envscan: the saved tier cannot be read, so this runs plain; `envscan config tier` rewrites it");
                Tier::Plain
            }
            Saved::Live => match config::api_key() {
                Ok(key) => Tier::Live { key },
                Err(reason) => Tier::Fallback(reason.to_string()),
            },
        }
    }

    /// Send what may be sent. On success the candidates become the verdicts' survivors, and
    /// on failure the plain candidates stand untouched.
    fn run(self, scan: &mut Scan, args: &ScanArgs) -> Ran {
        match self {
            Tier::Plain => Ran { label: "plain".to_string(), judgement: None },
            Tier::Fallback(reason) => Ran::fallback(&reason),
            Tier::Live { key } => match judge_pending(scan, &key, args.max_candidates) {
                Ok(judgement) => Ran { label: format!("live ({})", judge::MODEL), judgement: Some(judgement) },
                Err(reason) => Ran::fallback(&reason),
            },
        }
    }
}

struct Ran {
    label: String,
    judgement: Option<Judgement>,
}

impl Ran {
    fn fallback(reason: &str) -> Ran {
        Ran { label: format!("plain (fallback from live: {reason})"), judgement: None }
    }
}

fn judge_pending(scan: &mut Scan, key: &str, max_candidates: usize) -> Result<Judgement, String> {
    let pending = std::mem::take(&mut scan.pending);
    let mut request_of: HashMap<String, usize> = HashMap::new();
    let mut requests: Vec<judge::Line> = Vec::new();
    let mut lines_withheld = 0;
    for flagged in &pending {
        if flagged.withheld {
            lines_withheld += 1;
        } else if !request_of.contains_key(flagged.text.as_str()) {
            request_of.insert(flagged.text.clone(), requests.len());
            requests.push(judge::Line {
                path: flagged.path.clone(),
                text: flagged.text.clone(),
                values: flagged.found.iter().map(|f| f.value.clone()).collect(),
            });
        }
    }
    let candidates_sent: usize = requests.iter().map(|r| r.values.len()).sum();
    eprintln!(
        "envscan: judging {} lines, {candidates_sent} candidates, about ${:.4}",
        requests.len(),
        judge::estimate_usd(candidates_sent)
    );
    if candidates_sent > max_candidates {
        return Err(format!("{candidates_sent} candidates, limit {max_candidates}"));
    }
    let client = judge::Client::from_env(key)?;
    let verdicts = judge::judge(&client, &requests)?;

    let mut judgement = Judgement {
        lines_sent: requests.len(),
        candidates_sent,
        lines_withheld,
        files_known_only: scan.scanned.saturating_sub(scan.sendable_files),
        ..Judgement::default()
    };
    let mut tallies: BTreeMap<(&'static str, String), Tally> = BTreeMap::new();
    for flagged in pending {
        let line_verdicts = (!flagged.withheld).then(|| &verdicts[request_of[flagged.text.as_str()]]);
        for (i, found) in flagged.found.into_iter().enumerate() {
            let verdict = line_verdicts.map(|v| &v[i]);
            if let Some(verdict) = verdict {
                if verdict.p > judge::THRESHOLD {
                    judgement.kept += 1;
                } else {
                    judgement.rejected += 1;
                    continue;
                }
            }
            let tally = tallies.entry((found.shape, found.value)).or_default();
            tally.add(&flagged.at, flagged.input, scan.full);
            if let Some(verdict) = verdict {
                if tally.p.is_none_or(|p| verdict.p > p) {
                    tally.p = Some(verdict.p);
                    tally.kind = Some(verdict.kind.clone());
                }
            }
        }
    }
    scan.candidates = tallies;
    Ok(judgement)
}

fn fail(message: &str) -> Exit {
    eprintln!("envscan: {message}");
    Exit::Error
}

fn finish(scan: Scan, env_file: &EnvFile, args: &ScanArgs, ran: Ran, warn: &[String]) -> Exit {
    let rules_loaded = scan.matcher.rules().len();
    let files_scanned = scan.scanned;
    let errors = scan.errors;
    let unscanned = scan.data_files.iter().filter(|d| !d.scanned).count();
    let leaks: Vec<Leak> = scan.leaks.into_values().collect();
    // A key marked `match: warn` never counts as a leak; only its whole-word hits are reported.
    let (warned, mut leaks): (Vec<Leak>, Vec<Leak>) = leaks.into_iter().partition(|l| warn.contains(&l.key));
    let warnings: Vec<Leak> = warned.into_iter().filter(|l| l.strict > 0).map(|l| Leak { loose: 0, ..l }).collect();
    leaks.sort_by(|a, b| (b.strict + b.loose).cmp(&(a.strict + a.loose)).then(a.key.cmp(&b.key)));
    let total_hits: usize = leaks.iter().map(|l| l.strict + l.loose).sum();

    let candidates_total = scan.candidates.len();
    let mut candidates_by_kind = BTreeMap::new();
    for (kind, _) in scan.candidates.keys() {
        *candidates_by_kind.entry(kind.to_string()).or_insert(0) += 1;
    }
    let mut ranked: Vec<((&'static str, String), Tally)> = scan.candidates.into_iter().collect();
    ranked.sort_by(|((ka, va), a), ((kb, vb), b)| {
        extract::weight(kb)
            .cmp(&extract::weight(ka))
            .then(b.files.cmp(&a.files))
            .then(b.hits.cmp(&a.hits))
            .then(ka.cmp(kb))
            .then(va.cmp(vb))
    });
    if !args.full {
        ranked.truncate(args.top);
    }
    let candidates = ranked
        .into_iter()
        .map(|((kind, value), tally)| Candidate {
            kind: kind.to_string(),
            masked: extract::mask(&value),
            files: tally.files,
            hits: tally.hits,
            first: tally.first,
            p: tally.p,
            judged_kind: tally.kind,
            value: args.full.then_some(value),
            at: tally.at,
        })
        .collect();

    let report = Report {
        tier: ran.label,
        rules_loaded,
        short_values: env_file.short_keys(),
        env_unparsed_lines: env_file.unparsed_lines.clone(),
        files_scanned,
        skipped: scan.skipped,
        extractor_errors: scan.extractor_errors,
        leaks,
        warnings,
        data_files: scan.data_files,
        candidates_total,
        candidates_by_kind,
        candidates,
        judgement: ran.judgement,
        full: args.full,
    };
    let rendered = if args.json { report.to_json() } else { report.to_text() };
    let mut stdout = std::io::stdout();
    if writeln!(stdout, "{}", rendered.trim_end()).and_then(|_| stdout.flush()).is_err() {
        // The caller reads this exit code, so a report it never got cannot look clean.
        return Exit::Error;
    }

    for error in &errors {
        eprintln!("envscan: {error}");
    }
    if unscanned > 0 {
        eprintln!("envscan: {unscanned} data files unscanned: this is not a clean result");
    }
    let exit = Exit::decide(total_hits, rules_loaded, files_scanned, errors.len() + unscanned);
    match exit {
        Exit::NoRules => eprintln!("envscan: 0 rules loaded: this is not a clean result"),
        Exit::Error if files_scanned == 0 && errors.is_empty() => {
            eprintln!("envscan: nothing scanned: this is not a clean result")
        }
        _ => {}
    }
    exit
}

/// The result of one input, before it is attributed to a display path.
enum Outcome {
    Scanned { hits: Vec<Hit>, bytes: Vec<u8>, broad: Broad },
    /// `hits` is `None` when the file was only listed.
    Data { format: String, size: u64, hits: Option<BTreeMap<usize, RuleHits>> },
    Large,
    Binary,
    NonUtf8,
    Unreadable(String),
}

/// What the extractor made of one input.
#[derive(Default)]
struct Broad {
    /// `(line number, candidate)`, without any value the known-value rules already report.
    found: Vec<(usize, Found)>,
    long_lines: usize,
    errors: usize,
    /// Flagged lines with their text, kept only for a file that may be sent.
    sendable: Option<Vec<(usize, String, Vec<Found>, bool)>>,
}

fn extract_text(matcher: &Matcher, text: &str, sendable: bool) -> Broad {
    let mut broad = Broad { sendable: sendable.then(Vec::new), ..Broad::default() };
    for (i, line) in extract::lines(text).enumerate() {
        if line.len() > extract::MAX_LINE_BYTES {
            broad.long_lines += 1;
            continue;
        }
        let extraction = extract::extract(line);
        broad.errors += extraction.errors;
        // Already a leak, by key: its mask would print part of a known value.
        let found: Vec<Found> =
            extraction.found.into_iter().filter(|f| matcher.find(f.value.as_bytes()).is_empty()).collect();
        if let (Some(sendable), false) = (&mut broad.sendable, found.is_empty()) {
            // The whole line goes to the vendor, so any known value in it withholds all of it.
            let withheld = !matcher.find(line.as_bytes()).is_empty();
            sendable.push((i + 1, line.to_string(), found.clone(), withheld));
        }
        broad.found.extend(found.into_iter().map(|f| (i + 1, f)));
    }
    broad
}

/// One candidate across the scan.
#[derive(Default)]
struct Tally {
    files: usize,
    hits: usize,
    first: String,
    /// Every location, filled only under `--full`.
    at: Vec<String>,
    last_file: usize,
    p: Option<f64>,
    kind: Option<String>,
}

impl Tally {
    fn add(&mut self, at: &str, input: usize, full: bool) {
        if self.hits == 0 {
            self.first = at.to_string();
        }
        if self.last_file != input {
            self.files += 1;
            self.last_file = input;
        }
        self.hits += 1;
        if full {
            self.at.push(at.to_string());
        }
    }
}

/// A flagged line of a file that may be sent, waiting for the tier to run.
struct Flagged {
    path: String,
    at: String,
    input: usize,
    text: String,
    found: Vec<Found>,
    withheld: bool,
}

fn scan_file(matcher: &Matcher, path: &Path, extract: bool, sendable: bool) -> Outcome {
    match std::fs::metadata(path) {
        Ok(meta) if meta.len() > MAX_FILE_BYTES => return Outcome::Large,
        Ok(_) => {}
        Err(e) => return Outcome::Unreadable(e.to_string()),
    }
    match std::fs::read(path) {
        Ok(bytes) => {
            let under_limit = (bytes.len() as u64) < MAX_FILE_BYTES;
            scan_bytes(matcher, &bytes, extract, sendable && under_limit)
        }
        Err(e) => Outcome::Unreadable(e.to_string()),
    }
}

/// Headers are never read: an unscanned form is listed from its metadata alone.
fn scan_data_file(matcher: &Matcher, path: &Path, format: String, full: bool) -> Outcome {
    let size = match std::fs::metadata(path) {
        Ok(meta) => meta.len(),
        Err(e) => return Outcome::Unreadable(e.to_string()),
    };
    if !extract::is_text_data(&format) {
        return Outcome::Data { format, size, hits: None };
    }
    let streamed = std::fs::File::open(path)
        .and_then(|file| data::stream(matcher, file, if full { usize::MAX } else { AT_CAP }));
    match streamed {
        Ok(Streamed::Scanned(hits)) => Outcome::Data { format, size, hits: Some(hits) },
        Ok(Streamed::NotText) => Outcome::Data { format, size, hits: None },
        Err(e) => Outcome::Unreadable(e.to_string()),
    }
}

fn scan_bytes(matcher: &Matcher, bytes: &[u8], extract: bool, sendable: bool) -> Outcome {
    if memchr::memchr(0, &bytes[..bytes.len().min(SNIFF_BYTES)]).is_some() {
        return Outcome::Binary;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Outcome::NonUtf8;
    };
    let broad = if extract { extract_text(matcher, text, sendable) } else { Broad::default() };
    let hits = matcher.find(bytes);
    // Keep the text only when a hit needs its line number.
    let bytes = if hits.is_empty() { Vec::new() } else { bytes.to_vec() };
    Outcome::Scanned { hits, bytes, broad }
}

fn line_of(bytes: &[u8], offset: usize) -> usize {
    memchr::memchr_iter(b'\n', &bytes[..offset]).count() + 1
}

struct Scan<'a> {
    matcher: &'a Matcher,
    full: bool,
    scanned: usize,
    skipped: Skipped,
    errors: Vec<String>,
    leaks: BTreeMap<String, Leak>,
    data_files: Vec<DataFile>,
    extractor_errors: usize,
    candidates: BTreeMap<(&'static str, String), Tally>,
    pending: Vec<Flagged>,
    sendable_files: usize,
    /// Counts absorbed inputs, so a candidate can tell a new file from its last one.
    input: usize,
}

impl<'a> Scan<'a> {
    fn new(matcher: &'a Matcher, full: bool) -> Self {
        Scan {
            matcher,
            full,
            scanned: 0,
            skipped: Skipped::default(), errors: Vec::new(), leaks: BTreeMap::new(),
            data_files: Vec::new(),
            extractor_errors: 0,
            candidates: BTreeMap::new(),
            pending: Vec::new(),
            sendable_files: 0,
            input: 0,
        }
    }

    /// A report path can hold a known value, so it is rewritten unless `--full` was asked for.
    fn shown(&self, display: &str) -> String {
        if self.full { display.to_string() } else { self.matcher.redact(display) }
    }

    fn absorb_name(&mut self, display: &str, hits: &[Hit]) {
        let at = self.shown(display);
        for hit in hits {
            self.record(hit, at.clone());
        }
    }

    fn absorb(&mut self, display: &str, outcome: Outcome) {
        match outcome {
            Outcome::Scanned { hits, bytes, broad } => {
                self.scanned += 1;
                self.input += 1;
                let shown = self.shown(display);
                self.skipped.long_lines += broad.long_lines;
                self.extractor_errors += broad.errors;
                if let Some(sendable) = broad.sendable {
                    self.sendable_files += 1;
                    // The path is sent too, and a path can hold a known value.
                    let path_holds_known = !self.matcher.find(display.as_bytes()).is_empty();
                    for (line, text, found, withheld) in sendable {
                        self.pending.push(Flagged {
                            path: display.to_string(),
                            at: format!("{shown}:{line}"),
                            input: self.input,
                            text,
                            found,
                            withheld: withheld || path_holds_known,
                        });
                    }
                }
                for (line, found) in broad.found {
                    let at = format!("{shown}:{line}");
                    let (input, full) = (self.input, self.full);
                    self.candidates.entry((found.shape, found.value)).or_default().add(&at, input, full);
                }
                for hit in hits {
                    let at = format!("{shown}:{}", line_of(&bytes, hit.start));
                    self.record(&hit, at);
                }
            }
            Outcome::Data { format, size, hits } => {
                let shown = self.shown(display);
                let scanned = hits.is_some();
                if scanned {
                    self.scanned += 1;
                }
                for (rule, rule_hits) in hits.unwrap_or_default() {
                    self.record_data(rule, &rule_hits, &shown);
                }
                self.data_files.push(DataFile {
                    path: shown,
                    format,
                    shape: format!("{size} bytes"),
                    scanned,
                });
            }
            Outcome::Large => self.skipped.large += 1,
            Outcome::Binary => self.skipped.binary += 1,
            Outcome::NonUtf8 => self.skipped.non_utf8 += 1,
            Outcome::Unreadable(e) => {
                let shown = self.matcher.redact(display);
                self.errors.push(format!("cannot read {shown}: {e}"));
            }
        }
    }

    fn record_data(&mut self, rule: usize, hits: &RuleHits, shown: &str) {
        let full = self.full;
        for key in &self.matcher.rules()[rule].keys {
            let leak = self.leaks.entry(key.clone()).or_insert_with(|| Leak { key: key.clone(), ..Leak::default() });
            leak.strict += hits.strict;
            leak.loose += hits.loose;
            for line in &hits.lines {
                let at = format!("{shown}:{line}");
                if (full || leak.at.len() < AT_CAP) && !leak.at.contains(&at) {
                    leak.at.push(at);
                }
            }
        }
    }

    fn record(&mut self, hit: &Hit, at: String) {
        let full = self.full;
        for key in &self.matcher.rules()[hit.rule].keys {
            let leak = self.leaks.entry(key.clone()).or_insert_with(|| Leak { key: key.clone(), ..Leak::default() });
            if hit.strict { leak.strict += 1 } else { leak.loose += 1 }
            if (full || leak.at.len() < AT_CAP) && !leak.at.contains(&at) {
                leak.at.push(at.clone());
            }
        }
    }
}
