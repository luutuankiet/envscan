//! The broad candidate extractor: 13 ordered shapes run per line, a later span overlapping an
//! earlier one dropped. A port of the Python `extract()` held to it by a golden test; see
//! `tests/fixtures/broad/README.md`. Offsets are characters, as in Python.

use fancy_regex::{Regex, RegexBuilder};
use std::sync::OnceLock;

/// A longer line gets known-value matching only, because backtracking cost grows with length.
pub const MAX_LINE_BYTES: usize = 4096;

/// Order is priority. Python's `\s` also holds U+001C to U+001F, which `home-path` spells out so
/// that all of ASCII agrees.
const SHAPES: &[(&str, &str)] = &[
    ("bucket", r"\b(?:gs|s3)://[A-Za-z0-9._-]+"),
    ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ("url-host", r"(?<=://)[A-Za-z0-9.-]+"),
    ("gh-repo", r"(?<=github\.com/)[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"),
    ("home-path", "(?:/home|/Users)/[^\\s\\x1c-\\x1f\"'`:,)]+"),
    ("ip", r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?(?![\d])"),
    ("filename", r"[A-Za-z0-9_.-]+\.(?:csv|xlsx|pdf|txt|parquet)\b"),
    ("hostname", r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\.[a-z]{2,}\b|\b[a-z0-9-]+\.(?:internal|lan|local|corp)\b"),
    ("owner-repo", r"(?<![/\w.-])[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9_.-]*(?![/\w])"),
    ("account-id", r"\b\d{12}\b"),
    ("handle", r"(?<![\w.])@[a-z][a-z0-9_-]+"),
    ("slug", r"\b[a-z][a-z0-9]*(?:-[a-z0-9]+){1,}\b"),
    ("proper-noun", r"\b[A-Z][a-z]{3,}(?: [A-Z][a-z]{3,})*\b"),
];

const COMMON_CAPS: &[&str] = &[
    "Session", "Context", "Client", "What", "Open", "Questions", "Decisions", "Should", "Probably",
    "Retried", "Exported", "Ask", "Upgrade", "Keep", "Nothing", "Ping", "Move", "Delete", "Confirm",
    "Notes", "Steps", "Opened", "Compared", "Checked", "Handoff", "Dashboard", "Their", "Landing",
    "Repo", "Remember", "Another", "Look", "Compare", "Measure", "Write", "Version", "Public",
    "Scratch", "Old", "Prod", "Raw", "The", "This", "That", "Ran", "Retry", "Use", "Weekly", "Monday",
    "Thursday", "Timezone", "Try", "Moved", "Done", "Starting",
];

/// Data files take known-value matching only, and their headers are never read.
const DATA_EXTENSIONS: &[&str] = &[
    "csv", "tsv", "jsonl", "ndjson", "xlsx", "xls", "parquet", "sqlite", "db", "avro", "orc", "hyper",
    "twbx", "tdsx",
];

pub fn is_data_file(name: &str) -> bool {
    name.rsplit_once('.').is_some_and(|(_, ext)| DATA_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub value: String,
    pub shape: &'static str,
}

#[derive(Debug, Default)]
pub struct Extraction {
    pub found: Vec<Found>,
    /// Shapes that stopped on a regex runtime error, so this line may hold more than `found`.
    pub errors: usize,
}

type Compiled = Vec<(&'static str, Regex)>;

fn compile(backtrack_limit: Option<usize>) -> Compiled {
    SHAPES
        .iter()
        .map(|(shape, pattern)| {
            let mut builder = RegexBuilder::new(pattern);
            if let Some(limit) = backtrack_limit {
                builder.backtrack_limit(limit);
            }
            (*shape, builder.build().expect("the shapes are fixed and tested"))
        })
        .collect()
}

fn run(shapes: &Compiled, line: &str) -> Extraction {
    let mut out = Extraction::default();
    let mut taken: Vec<(usize, usize)> = Vec::new();
    for (shape, regex) in shapes {
        for found in regex.find_iter(line) {
            let m = match found {
                Ok(m) => m,
                Err(_) => {
                    out.errors += 1;
                    break;
                }
            };
            let (start, end) = (m.start(), m.end());
            if taken.iter().any(|(s, e)| start < *e && *s < end) {
                continue;
            }
            let value = m.as_str().trim_end_matches('.');
            if *shape == "proper-noun"
                && (COMMON_CAPS.contains(&value) || line[..start].chars().take(3).count() <= 2)
            {
                continue;
            }
            if *shape == "ip" && value.matches('.').count() != 3 {
                continue;
            }
            // An empty value still holds its span, so later shapes see what Python's see.
            taken.push((start, end));
            if !value.is_empty() {
                out.found.push(Found { value: value.to_string(), shape });
            }
        }
    }
    out
}

/// The ordered `(value, shape)` list of one line, which holds no `\n`.
pub fn extract(line: &str) -> Extraction {
    static SHAPES_COMPILED: OnceLock<Compiled> = OnceLock::new();
    run(SHAPES_COMPILED.get_or_init(|| compile(None)), line)
}

/// Split on `\n` with one trailing `\r` removed. Rust's `lines()` is the same rule, named here
/// because Python's `splitlines()` is not, and line numbers depend on it.
pub fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
}

/// First two characters plus length in characters. A value that short shows nothing.
pub fn mask(value: &str) -> String {
    let length = value.chars().count();
    if length <= 2 {
        return format!("...({length})");
    }
    let head: String = value.chars().take(2).collect();
    format!("{head}...({length})")
}

pub fn weight(shape: &str) -> u8 {
    match shape {
        "home-path" | "email" => 5,
        "ip" | "hostname" | "account-id" => 4,
        "bucket" => 3,
        "gh-repo" | "owner-repo" | "url-host" | "handle" => 2,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_runtime_error_is_counted_never_silent() {
        let tiny = compile(Some(1));
        let out = run(&tiny, "foo/bar.Baz 1.2.3.4 @someone");
        assert!(out.errors > 0);
    }

    #[test]
    fn an_empty_value_is_dropped_but_holds_its_span() {
        let out = extract("x://...");
        assert!(out.found.is_empty(), "{:?}", out.found);
        assert_eq!(out.errors, 0);
    }

    #[test]
    fn the_proper_noun_offset_is_in_characters() {
        assert!(extract("é Quillon").found.is_empty());
        assert_eq!(extract("abc Quillon").found.len(), 1);
    }

    #[test]
    fn masks_show_two_characters_and_the_length() {
        assert_eq!(mask("zqxvalue"), "zq...(8)");
        assert_eq!(mask("日本語の"), "日本...(4)");
        assert_eq!(mask("ab"), "...(2)");
    }

    #[test]
    fn data_files_are_known_by_extension_ignoring_case() {
        assert!(is_data_file("a.CSV") && is_data_file("b.c.parquet"));
        assert!(!is_data_file("csv") && !is_data_file("a.md"));
    }
}
