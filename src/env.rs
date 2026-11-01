//! Finding and reading the `.env` that holds known values. Shared by every subcommand and
//! by the outbound gate, so discovery has exactly one definition.

use crate::matcher::Rule;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// `--env`, else `.env` at the work tree's top level, else at the parent of the common git
/// directory. A linked worktree has no `.env` of its own, so a nearest-file rule would fail
/// open exactly where agents work.
pub fn discover(explicit: Option<&Path>, cwd: &Path) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return Some(path.to_path_buf());
    }
    at_repo_root(cwd, ".env")
}

/// The key list used when no `.env` exists, as on a fresh machine. Found the way `discover`
/// finds `.env`. When a `.env` exists, its key list is the `.env.example` beside it.
pub fn discover_example(cwd: &Path) -> Option<PathBuf> {
    at_repo_root(cwd, ".env.example")
}

fn at_repo_root(cwd: &Path, name: &str) -> Option<PathBuf> {
    if let Some(top) = rev_parse(cwd, "--show-toplevel") {
        let candidate = cwd.join(top).join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    let common = cwd.join(rev_parse(cwd, "--git-common-dir")?).canonicalize().ok()?;
    let candidate = common.parent()?.join(name);
    candidate.is_file().then_some(candidate)
}

fn rev_parse(cwd: &Path, flag: &str) -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", flag])
        .current_dir(cwd)
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let text = text.trim_end_matches(['\r', '\n']);
    (!text.is_empty()).then(|| text.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub key: String,
    pub value: String,
    pub line: usize,
}

/// A parsed `.env`. It is never sourced, and an unparsable line is known by number only.
#[derive(Debug, Default, Clone)]
pub struct EnvFile {
    pub entries: Vec<Entry>,
    pub unparsed_lines: Vec<usize>,
}

impl EnvFile {
    pub fn load(path: &Path) -> io::Result<EnvFile> {
        Ok(EnvFile::parse(&std::fs::read(path)?))
    }

    pub fn parse(bytes: &[u8]) -> EnvFile {
        let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
        let mut file = EnvFile::default();
        for (i, raw) in bytes.split(|b| *b == b'\n').enumerate() {
            let line = i + 1;
            let Ok(text) = std::str::from_utf8(raw) else {
                file.unparsed_lines.push(line);
                continue;
            };
            let text = text.trim();
            if text.is_empty() || text.starts_with('#') {
                continue;
            }
            match parse_line(text) {
                Some((key, value)) => file.entries.push(Entry { key, value, line }),
                None => file.unparsed_lines.push(line),
            }
        }
        file
    }

    /// Values of three or more characters, one rule per distinct value ignoring case, each
    /// carrying every key that holds it, so a duplicate is reported under all of them.
    pub fn rules(&self) -> Vec<Rule> {
        let mut rules: Vec<Rule> = Vec::new();
        let mut index: HashMap<String, usize> = HashMap::new();
        for entry in &self.entries {
            if entry.value.chars().count() < 3 {
                continue;
            }
            let i = *index.entry(entry.value.to_lowercase()).or_insert_with(|| {
                rules.push(Rule { value: entry.value.clone(), keys: Vec::new() });
                rules.len() - 1
            });
            if !rules[i].keys.contains(&entry.key) {
                rules[i].keys.push(entry.key.clone());
            }
        }
        rules
    }

    /// Keys whose value is 1 to 2 characters: too short to match, so reported by key.
    pub fn short_keys(&self) -> Vec<String> {
        self.keys_where(|n| (1..=2).contains(&n))
    }

    /// Keys listed with no value. These are not short values.
    pub fn empty_keys(&self) -> Vec<String> {
        self.keys_where(|n| n == 0)
    }

    fn keys_where(&self, keep: impl Fn(usize) -> bool) -> Vec<String> {
        let mut keys: Vec<String> = Vec::new();
        for entry in &self.entries {
            if keep(entry.value.chars().count()) && !keys.contains(&entry.key) {
                keys.push(entry.key.clone());
            }
        }
        keys
    }
}

fn parse_line(text: &str) -> Option<(String, String)> {
    let body = match text.strip_prefix("export") {
        Some(rest) if rest.starts_with(char::is_whitespace) => rest,
        _ => text,
    };
    let (key, value) = body.split_once('=')?;
    let key = key.trim();
    let mut chars = key.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_')
        || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    let value = unquote(value.trim());
    // Only spaces between quotes would match every gap in every file.
    let value = if value.trim().is_empty() { "" } else { value };
    Some((key.to_string(), value.to_string()))
}

fn unquote(value: &str) -> &str {
    for quote in ['"', '\''] {
        if value.len() >= 2 && value.starts_with(quote) && value.ends_with(quote) {
            return &value[1..value.len() - 1];
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(file: &EnvFile) -> Vec<(&str, &str)> {
        file.entries.iter().map(|e| (e.key.as_str(), e.value.as_str())).collect()
    }

    #[test]
    fn tolerates_whitespace_bom_crlf_export_and_quotes() {
        let f = EnvFile::parse(
            b"\xef\xbb\xbfFIRST=one1\r\n  SPACED  =  two2  \nexport THIRD=three\nQ=\"four\"\nS='five'\n",
        );
        assert_eq!(
            pairs(&f),
            [("FIRST", "one1"), ("SPACED", "two2"), ("THIRD", "three"), ("Q", "four"), ("S", "five")]
        );
        assert!(f.unparsed_lines.is_empty());
    }

    #[test]
    fn unparsable_lines_are_numbered_and_comments_are_not_unparsable() {
        let f = EnvFile::parse(b"# note\n\nno equals\n1DIGIT=x\nBAD KEY=y\nexportFOO BAR\nOK=fine\n=v\n\xff\xfe=z\n");
        assert_eq!(f.unparsed_lines, [3, 4, 5, 6, 8, 9]);
        assert_eq!(pairs(&f), [("OK", "fine")]);
    }

    #[test]
    fn lengths_are_characters_and_empty_is_not_short() {
        let f = EnvFile::parse("EMPTY=\nQEMPTY=\"\"\nBLANK=\"    \"\nONE=a\nTWO=é€\nTHREE=é€a\n".as_bytes());
        assert_eq!(f.empty_keys(), ["EMPTY", "QEMPTY", "BLANK"]);
        assert_eq!(f.short_keys(), ["ONE", "TWO"]);
        let rules = f.rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].keys, ["THREE"]);
    }

    #[test]
    fn a_duplicate_value_keeps_all_its_keys() {
        let f = EnvFile::parse(b"A=same\nB=SAME\nA=same\nC=other\n");
        let rules = f.rules();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].keys, ["A", "B"]);
        assert_eq!(rules[1].keys, ["C"]);
    }

    #[test]
    fn an_inline_comment_stays_in_the_value() {
        let f = EnvFile::parse(b"NOTE=value # note\n");
        assert_eq!(pairs(&f), [("NOTE", "value # note")]);
    }
}
