//! `envscan scan`: load rules, walk, match, report, choose the exit code.

use crate::cli::ScanArgs;
use crate::data::{self, RuleHits, Streamed};
use crate::env::{self, EnvFile};
use crate::exit::Exit;
use crate::extract::{self, Found};
use crate::matcher::{Hit, Matcher};
use crate::report::{Candidate, DataFile, Leak, Report, Skipped};
use crate::walker::{self, Options};
use rayon::prelude::*;
use std::collections::BTreeMap;
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
        let outcome = scan_bytes(&matcher, &bytes, !args.known_only);
        scan.absorb(STDIN_LABEL, outcome);
    }

    let walked = walker::walk(
        &roots,
        &cwd,
        &Options { no_ignore: args.no_ignore, rules_file: args.env.as_ref().map(|p| cwd.join(p)) },
    );
    scan.skipped.secret_named = walked.secret_named;
    scan.errors.extend(walked.errors.iter().map(|e| matcher.redact(e)));

    // Sorted input and an order-keeping collect keep the report deterministic.
    let outcomes: Vec<(Vec<Hit>, Option<Outcome>)> = walked
        .items
        .par_iter()
        .map(|item| {
            let name_hits = matcher.find(item.name.as_bytes());
            let outcome = item.is_file.then(|| match extract::data_format(&item.name) {
                Some(format) => scan_data_file(&matcher, &item.path, format, args.full),
                None => scan_file(&matcher, &item.path, !args.known_only),
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

    finish(scan, &env_file, args)
}

fn fail(message: &str) -> Exit {
    eprintln!("envscan: {message}");
    Exit::Error
}

fn finish(scan: Scan, env_file: &EnvFile, args: &ScanArgs) -> Exit {
    let rules_loaded = scan.matcher.rules().len();
    let files_scanned = scan.scanned;
    let errors = scan.errors;
    let unscanned = scan.data_files.iter().filter(|d| !d.scanned).count();
    let mut leaks: Vec<Leak> = scan.leaks.into_values().collect();
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
            value: args.full.then_some(value),
            at: tally.at,
        })
        .collect();

    let report = Report {
        tier: "plain".to_string(),
        rules_loaded,
        short_values: env_file.short_keys(),
        env_unparsed_lines: env_file.unparsed_lines.clone(),
        files_scanned,
        skipped: scan.skipped,
        extractor_errors: scan.extractor_errors,
        leaks,
        data_files: scan.data_files,
        candidates_total,
        candidates_by_kind,
        candidates,
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
}

fn extract_text(matcher: &Matcher, text: &str) -> Broad {
    let mut broad = Broad::default();
    for (i, line) in extract::lines(text).enumerate() {
        if line.len() > extract::MAX_LINE_BYTES {
            broad.long_lines += 1;
            continue;
        }
        let extraction = extract::extract(line);
        broad.errors += extraction.errors;
        for found in extraction.found {
            // Already a leak, by key: its mask would print part of a known value.
            if matcher.find(found.value.as_bytes()).is_empty() {
                broad.found.push((i + 1, found));
            }
        }
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
}

fn scan_file(matcher: &Matcher, path: &Path, extract: bool) -> Outcome {
    match std::fs::metadata(path) {
        Ok(meta) if meta.len() > MAX_FILE_BYTES => return Outcome::Large,
        Ok(_) => {}
        Err(e) => return Outcome::Unreadable(e.to_string()),
    }
    match std::fs::read(path) {
        Ok(bytes) => scan_bytes(matcher, &bytes, extract),
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

fn scan_bytes(matcher: &Matcher, bytes: &[u8], extract: bool) -> Outcome {
    if memchr::memchr(0, &bytes[..bytes.len().min(SNIFF_BYTES)]).is_some() {
        return Outcome::Binary;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Outcome::NonUtf8;
    };
    let broad = if extract { extract_text(matcher, text) } else { Broad::default() };
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
                for (line, found) in broad.found {
                    let at = format!("{shown}:{line}");
                    let tally = self.candidates.entry((found.shape, found.value)).or_default();
                    if tally.hits == 0 {
                        tally.first = at.clone();
                    }
                    if tally.last_file != self.input {
                        tally.files += 1;
                        tally.last_file = self.input;
                    }
                    tally.hits += 1;
                    if self.full {
                        tally.at.push(at);
                    }
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
