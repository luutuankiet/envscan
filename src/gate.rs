//! `envscan gate`: the outbound gate. A PreToolUse hook pipes its JSON here; git's pre-push
//! hook pipes its ref lines here with `--pre-push`. Exit 0 lets the call through, exit 2
//! denies it with a reason on stderr that names keys, never values.
//!
//! Only outbound calls are judged: `git commit`, `git push`, `gh` posting verbs, and GitHub
//! MCP tools other than the read tools. Everything else passes.

use crate::env::{self, EnvFile, Example};
use crate::exit::Exit;
use crate::matcher::{Matcher, Rule};
use clap::{Args, Subcommand};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
const ZERO_SHA: &str = "0000000000000000000000000000000000000000";
const MCP_READ_TOOLS: [&str; 3] = ["read_files", "grep", "directory_tree"];
const HOOK_LINE: &str = "envscan gate --pre-push \"$@\"";
const HOOK_SCRIPT: &str = "#!/bin/sh\n# Written by `envscan gate install`. Denies a push that carries a known value.\nbin=\"$(command -v envscan 2>/dev/null)\" || bin=\"$HOME/.local/bin/envscan\"\nexec \"$bin\" gate --pre-push \"$@\"\n";

#[derive(Args, Debug)]
pub struct GateArgs {
    #[command(subcommand)]
    pub action: Option<GateAction>,
    /// Run as git's pre-push hook: read `<local ref> <local sha> <remote ref> <remote sha>`
    /// lines on stdin and scan what would be pushed.
    #[arg(long)]
    pub pre_push: bool,
    /// The values file; defaults to `.env` at the repo root.
    #[arg(long, value_name = "FILE")]
    pub env: Option<PathBuf>,
    /// The remote name and URL git passes to pre-push. Unused.
    #[arg(hide = true)]
    pub rest: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum GateAction {
    /// Write the pre-push hook at `git rev-parse --git-path hooks`. Exit 0 written or already
    /// there, 2 refused (another hook or a tracked hooks directory), 3 not a git repo.
    Install,
}

pub fn run(args: &GateArgs) -> Exit {
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(e) => return deny(&format!("cannot read the working directory: {e}")),
    };
    if let Some(GateAction::Install) = args.action {
        return install(&cwd);
    }
    let mut stdin = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut stdin) {
        return deny(&format!("cannot read stdin: {e}"));
    }
    if args.pre_push {
        return match Gate::load(args.env.as_deref(), &cwd) {
            Ok(Some(gate)) => gate.pre_push(&cwd, &stdin),
            Ok(None) => Exit::Clean,
            Err(reason) => deny(&reason),
        };
    }
    let hook: serde_json::Value = match serde_json::from_str(&stdin) {
        Ok(v) => v,
        Err(_) => return deny("the hook input is not JSON"),
    };
    let cwd = hook.get("cwd").and_then(|v| v.as_str()).map(PathBuf::from).unwrap_or(cwd);
    let tool = hook.get("tool_name").and_then(|v| v.as_str()).unwrap_or("");
    let input = hook.get("tool_input").cloned().unwrap_or(serde_json::Value::Null);
    let call = if tool == "Bash" {
        let command = input.get("command").and_then(|v| v.as_str()).unwrap_or("");
        match parse_bash(command, &cwd) {
            Some(call) => call,
            None => return Exit::Clean,
        }
    } else if tool.starts_with("mcp__") && tool.contains("gh-cli__") {
        if MCP_READ_TOOLS.iter().any(|t| tool.ends_with(&format!("__{t}"))) {
            return Exit::Clean;
        }
        Call::Mcp(input)
    } else {
        return Exit::Clean;
    };
    match Gate::load(args.env.as_deref(), &cwd) {
        Ok(Some(gate)) => gate.judge(&call, &cwd),
        Ok(None) => Exit::Clean,
        Err(reason) => deny(&reason),
    }
}

fn deny(reason: &str) -> Exit {
    eprintln!("envscan gate: denied: {reason}");
    Exit::NoRules
}

/// One outbound call, as far as the gate needs to know it.
#[derive(Debug)]
enum Call {
    Bash(Bash),
    Mcp(serde_json::Value),
}

#[derive(Debug, Default)]
struct Bash {
    text: String,
    /// The reason to deny without scanning: an expansion, `eval`, `sh -c`, `xargs`,
    /// `--no-verify`, `-c core.hooksPath`, or a file the gate cannot read.
    refuse: Option<String>,
    commit_dirs: Vec<PathBuf>,
    push_dirs: Vec<PathBuf>,
    files: Vec<PathBuf>,
    gh: bool,
    /// A literal heredoc feeds stdin, so `--body-file -` reads text the gate has seen.
    literal_stdin: bool,
}

struct Gate {
    matcher: Matcher,
    short: Matcher,
    warn: Vec<String>,
    incomplete: Vec<String>,
}

#[derive(Default)]
struct Findings {
    deny: BTreeSet<String>,
    warn: BTreeSet<String>,
    places: BTreeSet<&'static str>,
}

impl Gate {
    /// `Ok(None)` when the repo has no `.env` and no `.env.example`: not opted in.
    fn load(explicit: Option<&Path>, cwd: &Path) -> Result<Option<Gate>, String> {
        let env_path = env::discover(explicit, cwd);
        let example = env::example_for(env_path.as_deref(), cwd);
        if env_path.is_none() && example.is_none() {
            return Ok(None);
        }
        let env_file = match &env_path {
            Some(p) => EnvFile::load(p).map_err(|e| format!("cannot read the env file: {e}"))?,
            None => EnvFile::default(),
        };
        let example = match &example {
            Some(p) => Example::load(p).map_err(|e| format!("cannot read .env.example: {e}"))?,
            None => Example::default(),
        };
        let listed: Vec<&String> = env_file.entries.iter().map(|e| &e.key).collect();
        let mut incomplete: Vec<String> =
            example.keys.iter().filter(|k| !listed.contains(k)).cloned().collect();
        for key in env_file.empty_keys() {
            if !incomplete.contains(&key) {
                incomplete.push(key);
            }
        }
        let matcher = Matcher::new(env_file.rules()).map_err(|e| format!("cannot build the rules: {e}"))?;
        let mut short_rules: Vec<Rule> = Vec::new();
        for e in env_file.entries.iter().filter(|e| (1..=2).contains(&e.value.chars().count())) {
            match short_rules.iter_mut().find(|r| r.value.to_lowercase() == e.value.to_lowercase()) {
                Some(r) if !r.keys.contains(&e.key) => r.keys.push(e.key.clone()),
                Some(_) => {}
                None => short_rules.push(Rule { value: e.value.clone(), keys: vec![e.key.clone()] }),
            }
        }
        let short = Matcher::new(short_rules).map_err(|e| format!("cannot build the rules: {e}"))?;
        Ok(Some(Gate { matcher, short, warn: example.warn, incomplete }))
    }

    fn preflight(&self) -> Option<String> {
        if !self.incomplete.is_empty() {
            return Some(format!(
                "protection is incomplete: these keys have no value in .env: {}. Fill them, then retry",
                self.incomplete.join(", ")
            ));
        }
        if self.matcher.rules().is_empty() && self.short.rules().is_empty() {
            return Some("0 rules loaded from .env: this is not a clean result".to_string());
        }
        None
    }

    fn judge(&self, call: &Call, cwd: &Path) -> Exit {
        if let Some(reason) = self.preflight() {
            return deny(&reason);
        }
        let mut found = Findings::default();
        match call {
            Call::Mcp(input) => {
                let text = input.to_string();
                self.check(text.as_bytes(), "the tool input", &mut found);
                let mut strings = Vec::new();
                json_strings(input, &mut strings);
                for s in &strings {
                    self.check(s.as_bytes(), "the tool input", &mut found);
                    for word in s.split_whitespace() {
                        let path = cwd.join(word.trim_start_matches('@'));
                        if path.is_file() {
                            if let Err(r) = self.check_file(&path, true, &mut found) {
                                return deny(&r);
                            }
                        }
                    }
                }
            }
            Call::Bash(bash) => {
                if let Some(reason) = &bash.refuse {
                    return deny(reason);
                }
                self.check(bash.text.as_bytes(), "the command", &mut found);
                for path in &bash.files {
                    if let Err(r) = self.check_file(path, bash.gh, &mut found) {
                        return deny(&r);
                    }
                }
                for dir in &bash.commit_dirs {
                    if let Err(r) = self.check_commit(dir, &mut found) {
                        return deny(&r);
                    }
                }
                for dir in &bash.push_dirs {
                    let refs = git(dir, &["for-each-ref", "--format=%(refname)", "refs/heads", "refs/tags"]);
                    match refs {
                        Some(refs) => self.check(refs.as_bytes(), "ref names", &mut found),
                        None => return deny("cannot list the refs to push"),
                    }
                    let range = ["--branches", "--tags", "--not", "--remotes"];
                    if let Err(r) = self.check_range(dir, &range, &mut found) {
                        return deny(&r);
                    }
                }
            }
        }
        self.verdict(found)
    }

    fn verdict(&self, found: Findings) -> Exit {
        if !found.warn.is_empty() {
            let keys: Vec<&str> = found.warn.iter().map(|s| s.as_str()).collect();
            eprintln!("envscan gate: warning: whole-word hits on keys marked match: warn: {}", keys.join(", "));
        }
        if found.deny.is_empty() {
            return Exit::Clean;
        }
        let keys: Vec<&str> = found.deny.iter().map(|s| s.as_str()).collect();
        let places: Vec<&str> = found.places.iter().copied().collect();
        deny(&format!(
            "known values in {}: {}. Write each as $KEY (envscan dehydrate), then retry",
            places.join(", "),
            keys.join(", ")
        ))
    }

    fn check(&self, bytes: &[u8], place: &'static str, found: &mut Findings) {
        self.check_once(bytes, place, found);
        if bytes.contains(&b'%') {
            self.check_once(&percent_decode(bytes), place, found);
        }
    }

    fn check_once(&self, bytes: &[u8], place: &'static str, found: &mut Findings) {
        let hits = self.matcher.find(bytes).into_iter().map(|h| (&self.matcher, h));
        let short = self.short.find(bytes).into_iter().filter(|h| h.strict).map(|h| (&self.short, h));
        for (m, hit) in hits.chain(short) {
            let keys = &m.rules()[hit.rule].keys;
            if keys.iter().all(|k| self.warn.contains(k)) {
                if hit.strict {
                    found.warn.extend(keys.iter().cloned());
                }
            } else {
                found.deny.extend(keys.iter().filter(|k| !self.warn.contains(k)).cloned());
                found.places.insert(place);
            }
        }
    }

    fn check_file(&self, path: &Path, deny_binary: bool, found: &mut Findings) -> Result<(), String> {
        let bytes = std::fs::read(path).map_err(|_| "a file the command names cannot be read".to_string())?;
        if deny_binary && is_binary(&bytes) {
            return Err("the command attaches a binary file".to_string());
        }
        self.check(path.to_string_lossy().as_bytes(), "a file name", found);
        self.check(&bytes, "a file the command names", found);
        Ok(())
    }

    /// `git diff HEAD`, untracked files and their names. A new binary file is denied.
    fn check_commit(&self, dir: &Path, found: &mut Findings) -> Result<(), String> {
        let base = if git(dir, &["rev-parse", "--verify", "-q", "HEAD"]).is_some() { "HEAD" } else { EMPTY_TREE };
        let diff = git(dir, &["diff", "--no-ext-diff", "--no-color", "--no-textconv", base])
            .ok_or("cannot read the working-tree diff")?;
        self.check(diff.as_bytes(), "the working-tree diff", found);
        let added = git(dir, &["diff", "--numstat", "--diff-filter=A", base]).ok_or("cannot read the diff")?;
        if added.lines().any(|l| l.starts_with("-\t-\t")) {
            return Err("the commit adds a binary file; the operator commits binaries by hand".to_string());
        }
        let untracked = git(dir, &["ls-files", "--others", "--exclude-standard", "-z"])
            .ok_or("cannot list untracked files")?;
        let top = git(dir, &["rev-parse", "--show-toplevel"]).ok_or("cannot find the repo root")?;
        let top = PathBuf::from(top.trim_end());
        for name in untracked.split('\0').filter(|n| !n.is_empty()) {
            self.check(name.as_bytes(), "untracked file names", found);
            let rel = git(dir, &["rev-parse", "--show-prefix"]).unwrap_or_default();
            let path = top.join(rel.trim_end()).join(name);
            let Ok(bytes) = std::fs::read(&path) else { continue };
            if is_binary(&bytes) {
                return Err("an untracked binary file would be committed; the operator commits binaries by hand".to_string());
            }
            self.check(&bytes, "untracked files", found);
        }
        Ok(())
    }

    /// Commits in a range: diffs, file names, authors, committers and messages.
    fn check_range(&self, dir: &Path, range: &[&str], found: &mut Findings) -> Result<(), String> {
        let mut log = vec!["log", "-p", "--no-ext-diff", "--no-color", "--no-textconv", "--format=%an <%ae>%n%cn <%ce>%n%B"];
        log.extend_from_slice(range);
        let text = git(dir, &log).ok_or("cannot read the commits to push")?;
        self.check(text.as_bytes(), "commits to push", found);
        let mut stat = vec!["log", "--numstat", "--diff-filter=A", "--format="];
        stat.extend_from_slice(range);
        let stat = git(dir, &stat).ok_or("cannot read the commits to push")?;
        if stat.lines().any(|l| l.starts_with("-\t-\t")) {
            return Err("the push adds a binary file; the operator pushes binaries by hand".to_string());
        }
        Ok(())
    }

    fn pre_push(&self, cwd: &Path, lines: &str) -> Exit {
        if let Some(reason) = self.preflight() {
            return deny(&reason);
        }
        let mut found = Findings::default();
        for line in lines.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let [local_ref, local_sha, remote_ref, remote_sha] = parts[..] else { continue };
            self.check(format!("{local_ref} {remote_ref}").as_bytes(), "ref names", &mut found);
            if local_sha == ZERO_SHA {
                continue;
            }
            if git(cwd, &["cat-file", "-t", local_sha]).as_deref().map(str::trim) == Some("tag") {
                match git(cwd, &["cat-file", "-p", local_sha]) {
                    Some(tag) => self.check(tag.as_bytes(), "tags", &mut found),
                    None => return deny("cannot read a tag to push"),
                }
            }
            let from = format!("^{remote_sha}");
            let range: Vec<&str> =
                if remote_sha == ZERO_SHA { vec![local_sha, "--not", "--remotes"] } else { vec![local_sha, &from] };
            if let Err(r) = self.check_range(cwd, &range, &mut found) {
                return deny(&r);
            }
        }
        self.verdict(found)
    }
}

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).current_dir(dir).stderr(Stdio::null()).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn is_binary(bytes: &[u8]) -> bool {
    bytes[..bytes.len().min(8192)].contains(&0)
}

fn percent_decode(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok());
            if let Some(b) = hex {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    out
}

fn json_strings(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(a) => a.iter().for_each(|v| json_strings(v, out)),
        serde_json::Value::Object(o) => o.values().for_each(|v| json_strings(v, out)),
        _ => {}
    }
}

/// `None` when the command holds no outbound verb.
fn parse_bash(command: &str, cwd: &Path) -> Option<Call> {
    let stripped = strip_literal_heredocs(command);
    let lexed = lex(&stripped);
    let mut bash = Bash { text: command.to_string(), literal_stdin: stripped.contains("<<LITERAL"), ..Bash::default() };
    let mut outbound = false;
    for words in &lexed.segments {
        let mut i = 0;
        // Prefixes the gate sees through.
        while i < words.len() {
            let w = words[i].as_str();
            let assignment = w.split_once('=').is_some_and(|(k, _)| {
                !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !k.starts_with(|c: char| c.is_ascii_digit())
            });
            if assignment || matches!(w, "rtk" | "proxy" | "env" | "command" | "exec" | "nohup" | "time" | "sudo" | "nice") {
                i += 1;
            } else {
                break;
            }
        }
        let Some(head) = words.get(i) else { continue };
        let name = head.rsplit('/').next().unwrap_or(head);
        let rest = &words[i + 1..];
        if name == "git" {
            let mut dir = cwd.to_path_buf();
            let mut j = 0;
            while j < rest.len() && rest[j].starts_with('-') {
                let flag = rest[j].as_str();
                if flag == "-C" || flag == "-c" || flag == "--git-dir" || flag == "--work-tree" || flag == "--namespace" {
                    let value = rest.get(j + 1).map(String::as_str).unwrap_or("");
                    if flag == "-C" {
                        dir = dir.join(value);
                    }
                    if flag == "-c" && value.to_lowercase().starts_with("core.hookspath") {
                        bash.refuse = Some("`-c core.hooksPath` beside an outbound verb".to_string());
                    }
                    j += 2;
                } else {
                    if flag.to_lowercase().contains("core.hookspath") {
                        bash.refuse = Some("`core.hooksPath` beside an outbound verb".to_string());
                    }
                    j += 1;
                }
            }
            let args = &rest[j.min(rest.len())..];
            match args.first().map(String::as_str) {
                Some("commit") => {
                    outbound = true;
                    bash.commit_dirs.push(dir.clone());
                    file_args(&args[1..], &dir, &["-F", "--file"], &mut bash);
                }
                Some("push") => {
                    outbound = true;
                    if args.iter().any(|a| a == "--no-verify") {
                        bash.refuse = Some("`git push --no-verify`".to_string());
                    }
                    bash.push_dirs.push(dir.clone());
                }
                _ => {}
            }
        } else if name == "gh" {
            let verbs: Vec<&str> = rest.iter().filter(|w| !w.starts_with('-')).take(2).map(String::as_str).collect();
            let posting = match verbs.as_slice() {
                ["issue" | "pr", v, ..] => matches!(*v, "create" | "comment" | "edit" | "review"),
                ["api" | "release" | "gist", ..] => true,
                ["repo", "create", ..] => true,
                _ => false,
            };
            if posting {
                outbound = true;
                bash.gh = true;
                file_args(rest, cwd, &["--body-file", "-F", "--field", "--input", "--notes-file"], &mut bash);
            }
        }
    }
    // `eval`, `sh -c` and `xargs` run text the gate cannot parse; a `git` or `gh` word
    // anywhere beside one makes the call outbound.
    let words = command.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    if !outbound && lexed.runner && words.into_iter().any(|w| w == "git" || w == "gh") {
        outbound = true;
    }
    if !outbound {
        return None;
    }
    if bash.refuse.is_none() {
        bash.refuse = lexed.refuse;
    }
    Some(Call::Bash(bash))
}

/// Every word that is an existing file is scanned. A file flag whose value the gate cannot
/// read (stdin, or a path that does not exist yet) is refused.
fn file_args(words: &[String], dir: &Path, flags: &[&str], bash: &mut Bash) {
    let mut i = 0;
    while i < words.len() {
        let w = &words[i];
        let (flag, inline) = match w.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v.to_string())),
            _ => (w.as_str(), None),
        };
        if flags.contains(&flag) {
            let value = inline.or_else(|| words.get(i + 1).cloned()).unwrap_or_default();
            let path = match value.split_once("=@") {
                Some((_, p)) => Some(p.to_string()),
                None if value.contains('=') => None,
                None => Some(value.trim_start_matches('@').to_string()),
            };
            if let Some(p) = path {
                if (p == "-" && !bash.literal_stdin) || (p != "-" && !dir.join(&p).is_file()) {
                    bash.refuse = Some(format!("`{flag}` names a file the gate cannot read; write it to a file first"));
                }
            }
        }
        for part in [w.as_str(), w.rsplit_once('=').map(|(_, v)| v).unwrap_or("")] {
            let candidate = dir.join(part.trim_start_matches('@'));
            if !part.is_empty() && candidate.is_file() && !bash.files.contains(&candidate) {
                bash.files.push(candidate);
            }
        }
        i += 1;
    }
}

/// Remove literal (quoted-delimiter) heredoc bodies, including the `"$(cat <<'EOF' ... EOF)"`
/// form agents write commit messages in, so their `$KEY` text is not read as an expansion.
fn strip_literal_heredocs(command: &str) -> String {
    let subst = fancy_regex::Regex::new(r#"(?s)\$\(\s*cat\s+<<-?\s*(['"])(\w+)\1[^\n]*\n.*?\n[ \t]*\2[ \t]*\n\s*\)"#)
        .expect("valid pattern");
    let text = subst.replace_all(command, "LITERAL").into_owned();
    let body = fancy_regex::Regex::new(r#"(?s)<<-?\s*(['"])(\w+)\1([^\n]*)\n.*?(\n[ \t]*\2[ \t]*(\n|$)|$)"#)
        .expect("valid pattern");
    body.replace_all(&text, "<<LITERAL$3\n").into_owned()
}

struct Lexed {
    segments: Vec<Vec<String>>,
    runner: bool,
    refuse: Option<String>,
}

/// Split into simple commands on `;`, `&`, `|`, newlines and parentheses, unquote words,
/// and note anything that runs text the gate cannot see: an expansion outside single quotes,
/// an unquoted heredoc, `eval`, `sh -c`, `xargs`.
fn lex(text: &str) -> Lexed {
    let mut segments: Vec<Vec<String>> = vec![Vec::new()];
    let mut refuse = None;
    let mut runner = false;
    let mut word = String::new();
    let mut in_word = false;
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    let mut quote: Option<char> = None;
    let flush = |segments: &mut Vec<Vec<String>>, word: &mut String, in_word: &mut bool| {
        if *in_word {
            segments.last_mut().unwrap().push(std::mem::take(word));
            *in_word = false;
        }
    };
    while i < chars.len() {
        let c = chars[i];
        match quote {
            Some('\'') => {
                if c == '\'' { quote = None } else { word.push(c) }
            }
            Some(_) => {
                if c == '"' {
                    quote = None;
                } else if c == '\\' && i + 1 < chars.len() {
                    i += 1;
                    word.push(chars[i]);
                } else {
                    if expands(&chars, i) {
                        refuse = Some("a `$VAR`, `$(...)` or backtick beside an outbound verb");
                    }
                    word.push(c);
                }
            }
            None => {
                if c == '\'' || c == '"' {
                    quote = Some(c);
                    in_word = true;
                } else if c == '\\' && i + 1 < chars.len() {
                    i += 1;
                    word.push(chars[i]);
                    in_word = true;
                } else if c.is_whitespace() && c != '\n' {
                    flush(&mut segments, &mut word, &mut in_word);
                } else if matches!(c, ';' | '&' | '|' | '\n' | '(' | ')' | '{' | '}') {
                    flush(&mut segments, &mut word, &mut in_word);
                    segments.push(Vec::new());
                } else {
                    if expands(&chars, i) {
                        refuse = Some("a `$VAR`, `$(...)` or backtick beside an outbound verb");
                    }
                    let after: String = chars[(i + 2).min(chars.len())..].iter().take(9).collect();
                    let heredoc = c == '<' && chars.get(i + 1) == Some(&'<') && chars.get(i + 2) != Some(&'<');
                    if heredoc && !after.trim_start_matches('-').trim_start().starts_with("LITERAL") {
                        refuse = Some("an unquoted heredoc beside an outbound verb; quote its delimiter");
                    }
                    word.push(c);
                    in_word = true;
                }
            }
        }
        i += 1;
    }
    flush(&mut segments, &mut word, &mut in_word);
    for words in &segments {
        for (k, w) in words.iter().enumerate() {
            let shell = matches!(w.as_str(), "sh" | "bash" | "zsh" | "dash");
            let dash_c = words.get(k + 1).is_some_and(|n| n.starts_with('-') && !n.starts_with("--") && n.contains('c'));
            if w == "eval" || w == "xargs" || (shell && dash_c) {
                refuse = Some("`eval`, `sh -c` or `xargs` beside an outbound verb");
                runner = true;
            }
        }
    }
    Lexed { segments, runner, refuse: refuse.map(str::to_string) }
}

fn expands(chars: &[char], i: usize) -> bool {
    match chars[i] {
        '`' => true,
        '$' => chars.get(i + 1).is_some_and(|n| n.is_ascii_alphanumeric() || "_{(@*#?!-".contains(*n)),
        _ => false,
    }
}

fn install(cwd: &Path) -> Exit {
    let Some(hooks) = git(cwd, &["rev-parse", "--git-path", "hooks"]) else {
        eprintln!("envscan gate install: not a git repository");
        return Exit::Error;
    };
    let hooks = cwd.join(hooks.trim_end());
    let refuse = |why: &str| {
        eprintln!("envscan gate install: refused: {why}. Add this line to the existing pre-push hook:\n  {HOOK_LINE}");
        Exit::NoRules
    };
    if git(cwd, &["config", "core.hooksPath"]).is_some() {
        let rel = hooks.to_string_lossy().into_owned();
        let tracked = git(cwd, &["ls-files", "--", &rel]).is_some_and(|o| !o.trim().is_empty());
        if tracked {
            return refuse("core.hooksPath points at a tracked directory");
        }
    }
    let path = hooks.join("pre-push");
    match std::fs::read_to_string(&path) {
        Ok(existing) if existing == HOOK_SCRIPT => {
            println!("envscan gate install: pre-push already installed");
            return Exit::Clean;
        }
        Ok(_) => return refuse("a different pre-push hook exists"),
        Err(_) if path.exists() => return refuse("a pre-push hook exists and cannot be read"),
        Err(_) => {}
    }
    let written = std::fs::create_dir_all(&hooks).and_then(|_| std::fs::write(&path, HOOK_SCRIPT)).and_then(|_| {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
    });
    match written {
        Ok(()) => {
            println!("envscan gate install: wrote the pre-push hook");
            Exit::Clean
        }
        Err(e) => {
            eprintln!("envscan gate install: cannot write the hook: {e}");
            Exit::Error
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(cmd: &str) -> Option<Bash> {
        match parse_bash(cmd, Path::new("/nonexistent-dir")) {
            Some(Call::Bash(b)) => Some(b),
            _ => None,
        }
    }

    #[test]
    fn non_outbound_commands_pass() {
        for cmd in ["ls -la", "git status", "git log --oneline", "gh issue view 3", "echo $HOME"] {
            assert!(call(cmd).is_none(), "{cmd}");
        }
    }

    #[test]
    fn prefixes_are_seen_through() {
        for cmd in ["rtk git commit -m x", "env A=b git push", "git -C sub commit -m x", "A=1 gh issue create --title t --body b"] {
            assert!(call(cmd).is_some(), "{cmd}");
        }
    }

    #[test]
    fn denied_outright() {
        for cmd in [
            "git push --no-verify",
            "git -c core.hooksPath=/dev/null push",
            "eval git push",
            "sh -c 'git push'",
            "echo x | xargs git commit -m",
            "git commit -m \"$MSG\"",
            "git commit -m \"$(date)\"",
            "gh issue create --body `cat f`",
            "gh issue create --body-file -",
            "gh issue create --body-file missing.md",
            "gh issue create -F body <<EOF\n$X\nEOF",
        ] {
            let b = call(cmd).unwrap_or_else(|| panic!("not outbound: {cmd}"));
            assert!(b.refuse.is_some(), "{cmd}");
        }
    }

    #[test]
    fn literal_heredocs_and_single_quotes_are_exempt() {
        for cmd in [
            "git commit -m 'uses $KEY'",
            "git commit -m \"$(cat <<'EOF'\nuses $KEY\nEOF\n)\"",
            "gh issue comment 3 --body-file - <<'EOF'\nuses $KEY\nEOF",
        ] {
            let b = call(cmd).unwrap_or_else(|| panic!("not outbound: {cmd}"));
            assert_eq!(b.refuse, None, "{cmd}");
        }
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode(b"a%20b%2Fc+d%zz"), b"a b/c d%zz");
    }
}
