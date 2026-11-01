//! `envscan scan`: load rules, walk, match, report, choose the exit code.

use crate::cli::ScanArgs;
use crate::env::{self, EnvFile};
use crate::exit::Exit;
use crate::matcher::{Hit, Matcher};
use crate::report::{Leak, Report, Skipped};
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
        let outcome = scan_bytes(&matcher, &bytes);
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
            (name_hits, item.is_file.then(|| scan_file(&matcher, &item.path)))
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
    let mut leaks: Vec<Leak> = scan.leaks.into_values().collect();
    leaks.sort_by(|a, b| (b.strict + b.loose).cmp(&(a.strict + a.loose)).then(a.key.cmp(&b.key)));
    let total_hits: usize = leaks.iter().map(|l| l.strict + l.loose).sum();

    let report = Report {
        tier: "plain".to_string(),
        rules_loaded,
        short_values: env_file.short_keys(),
        env_unparsed_lines: env_file.unparsed_lines.clone(),
        files_scanned,
        skipped: scan.skipped,
        leaks,
        ..Report::default()
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
    let exit = Exit::decide(total_hits, rules_loaded, files_scanned, errors.len());
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
    Scanned { hits: Vec<Hit>, bytes: Vec<u8> },
    Large,
    Binary,
    NonUtf8,
    Unreadable(String),
}

fn scan_file(matcher: &Matcher, path: &Path) -> Outcome {
    match std::fs::metadata(path) {
        Ok(meta) if meta.len() > MAX_FILE_BYTES => return Outcome::Large,
        Ok(_) => {}
        Err(e) => return Outcome::Unreadable(e.to_string()),
    }
    match std::fs::read(path) {
        Ok(bytes) => scan_bytes(matcher, &bytes),
        Err(e) => Outcome::Unreadable(e.to_string()),
    }
}

fn scan_bytes(matcher: &Matcher, bytes: &[u8]) -> Outcome {
    if memchr::memchr(0, &bytes[..bytes.len().min(SNIFF_BYTES)]).is_some() {
        return Outcome::Binary;
    }
    if std::str::from_utf8(bytes).is_err() {
        return Outcome::NonUtf8;
    }
    let hits = matcher.find(bytes);
    // Keep the text only when a hit needs its line number.
    let bytes = if hits.is_empty() { Vec::new() } else { bytes.to_vec() };
    Outcome::Scanned { hits, bytes }
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
}

impl<'a> Scan<'a> {
    fn new(matcher: &'a Matcher, full: bool) -> Self {
        Scan { matcher, full, scanned: 0, skipped: Skipped::default(), errors: Vec::new(), leaks: BTreeMap::new() }
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
            Outcome::Scanned { hits, bytes } => {
                self.scanned += 1;
                let shown = self.shown(display);
                for hit in hits {
                    let at = format!("{shown}:{}", line_of(&bytes, hit.start));
                    self.record(&hit, at);
                }
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
