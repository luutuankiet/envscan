//! `envscan hydrate` and `dehydrate`: move text between `$KEY` and real values.
//!
//! Text is bytes throughout, so anything that is not a listed key or known value comes out
//! exactly as it went in. A value is only ever printed by `hydrate` without `--check`.

use crate::cli::{DehydrateArgs, HydrateArgs};
use crate::env::{self, EnvFile};
use crate::exit::Exit;
use crate::matcher::{self, Matcher};
use regex::bytes::Regex;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const REFERENCE: &str = r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)";

#[derive(Debug, PartialEq, Eq)]
pub struct Filled {
    pub text: Vec<u8>,
    /// Listed keys the text names, in order of first appearance.
    pub used: Vec<String>,
    /// The subset of `used` with no value.
    pub missing: Vec<String>,
}

fn reference() -> Regex {
    Regex::new(REFERENCE).expect("the reference pattern is valid")
}

/// One pass, so a value holding `$OTHER` is not filled again. A name is read whole, as a shell
/// reads it: `$KEY_B` is never `$KEY` followed by `_B`.
pub fn fill(text: &[u8], listed: &HashSet<String>, values: &HashMap<String, String>) -> Filled {
    let mut out = Vec::with_capacity(text.len());
    let mut used = Vec::new();
    let mut missing = Vec::new();
    let mut at = 0;
    for caps in reference().captures_iter(text) {
        let name = caps.get(1).or_else(|| caps.get(2)).expect("one branch matched");
        let Ok(key) = std::str::from_utf8(name.as_bytes()) else { continue };
        if !listed.contains(key) {
            continue;
        }
        let whole = caps.get(0).expect("group 0 always exists");
        if !used.iter().any(|k| k == key) {
            used.push(key.to_string());
        }
        out.extend_from_slice(&text[at..whole.start()]);
        match values.get(key).filter(|v| !v.is_empty()) {
            Some(value) => out.extend_from_slice(value.as_bytes()),
            None => {
                if !missing.iter().any(|k| k == key) {
                    missing.push(key.to_string());
                }
            }
        }
        at = whole.end();
    }
    out.extend_from_slice(&text[at..]);
    Filled { text: out, used, missing }
}

/// Longest value first across the whole text, so a short value never splits a longer one that
/// overlaps it, whichever starts first. The match is the scanner's, case folded, so dehydrated
/// text passes the scan that gates it.
///
/// The name inside a `$NAME` or `${NAME}` is left alone even if it equals a value: otherwise a
/// value `home` would turn `$HOME` into `$$KEY`.
pub fn replace_values(text: &[u8], matcher: &Matcher) -> Vec<u8> {
    let names: Vec<(usize, usize)> = reference()
        .captures_iter(text)
        .filter_map(|caps| caps.get(1).or_else(|| caps.get(2)))
        .map(|m| (m.start(), m.end()))
        .collect();
    let in_a_name = |start: usize, end: usize| {
        let i = names.partition_point(|(_, name_end)| *name_end <= start);
        names.get(i).is_some_and(|(s, e)| *s <= start && end <= *e)
    };

    let mut hits = matcher.find(text);
    hits.retain(|h| !in_a_name(h.start, h.end));
    hits.sort_by_key(|h| (std::cmp::Reverse(h.end - h.start), h.start, h.rule));
    let mut taken = vec![false; text.len()];
    let mut chosen = Vec::new();
    for hit in hits {
        if !taken[hit.start..hit.end].iter().any(|t| *t) {
            taken[hit.start..hit.end].fill(true);
            chosen.push(hit);
        }
    }
    chosen.sort_by_key(|h| h.start);

    let mut out = Vec::with_capacity(text.len());
    let mut at = 0;
    for hit in chosen {
        out.extend_from_slice(&text[at..hit.start]);
        let key = &matcher.rules()[hit.rule].keys[0];
        let reference = if text.get(hit.end).is_some_and(|b| matcher::word(*b)) {
            format!("${{{key}}}")
        } else {
            format!("${key}")
        };
        out.extend_from_slice(reference.as_bytes());
        at = hit.end;
    }
    out.extend_from_slice(&text[at..]);
    out
}

pub fn run_hydrate(args: &HydrateArgs) -> Exit {
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(e) => return fail(&format!("cannot read the working directory: {e}")),
    };
    let files = match Files::load(args.env.as_deref(), &cwd) {
        Ok(files) => files,
        Err(e) => return fail(&e),
    };
    if files.env.is_none() && files.example.is_none() {
        eprintln!("envscan: no .env or .env.example found, so no key is listed");
        return Exit::NoRules;
    }
    let env_file = files.env.unwrap_or_default();
    warn_unparsed(&env_file);
    let text = match read_input(args.path.as_deref(), args.stdin, &env_file) {
        Ok(text) => text,
        Err(e) => return fail(&e),
    };

    let mut listed: HashSet<String> = env_file.entries.iter().map(|e| e.key.clone()).collect();
    if let Some(example) = &files.example {
        listed.extend(example.entries.iter().map(|e| e.key.clone()));
    }
    // Last definition wins, as when a shell reads the file.
    let values: HashMap<String, String> =
        env_file.entries.iter().map(|e| (e.key.clone(), e.value.clone())).collect();

    let filled = fill(&text, &listed, &values);
    if args.check {
        println!("keys used: {}", filled.used.join(" "));
    }
    if !filled.missing.is_empty() {
        eprintln!(
            "envscan: no value for: {}. Rebuild .env from .env.example.",
            filled.missing.join(" ")
        );
        return Exit::NoRules;
    }
    if args.check {
        println!("all keys resolve");
        return Exit::Clean;
    }
    write_output(&filled.text)
}

pub fn run_dehydrate(args: &DehydrateArgs) -> Exit {
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(e) => return fail(&format!("cannot read the working directory: {e}")),
    };
    let files = match Files::load(args.env.as_deref(), &cwd) {
        Ok(files) => files,
        Err(e) => return fail(&e),
    };
    let env_file = files.env.unwrap_or_default();
    warn_unparsed(&env_file);
    let matcher = match Matcher::new(env_file.rules()) {
        Ok(matcher) => matcher,
        Err(e) => return fail(&format!("cannot build the rules: {e}")),
    };
    // Text passed through with nothing to match against would look safe to post.
    if matcher.rules().is_empty() {
        eprintln!("envscan: no known values, so nothing can be replaced");
        return Exit::NoRules;
    }
    let short = env_file.short_keys();
    if !short.is_empty() {
        eprintln!("envscan: value under 3 characters, not replaced: {}", short.join(" "));
    }
    let text = match read_input(args.path.as_deref(), args.stdin, &env_file) {
        Ok(text) => text,
        Err(e) => return fail(&e),
    };
    write_output(&replace_values(&text, &matcher))
}

struct Files {
    env: Option<EnvFile>,
    example: Option<EnvFile>,
}

impl Files {
    /// An `--env` file that cannot be read is an error, never a fresh machine.
    fn load(explicit: Option<&Path>, cwd: &Path) -> Result<Files, String> {
        let env_path = env::discover(explicit, cwd);
        let env = match &env_path {
            Some(path) => Some(
                EnvFile::load(path).map_err(|e| format!("cannot read the env file: {e}"))?,
            ),
            None => None,
        };
        let example_path: Option<PathBuf> = match &env_path {
            Some(path) => Some(path.with_file_name(".env.example")),
            None => env::discover_example(cwd),
        };
        // Its keys only: a value written there is an example, never a value to fill.
        let example = match example_path.filter(|p| p.is_file()) {
            Some(path) => Some(
                EnvFile::load(&path).map_err(|e| format!("cannot read .env.example: {e}"))?,
            ),
            None => None,
        };
        Ok(Files { env, example })
    }
}

fn warn_unparsed(env_file: &EnvFile) {
    if !env_file.unparsed_lines.is_empty() {
        let lines: Vec<String> = env_file.unparsed_lines.iter().map(|n| n.to_string()).collect();
        eprintln!("envscan: env file lines not understood: {}", lines.join(" "));
    }
}

fn read_input(path: Option<&Path>, stdin: bool, env_file: &EnvFile) -> Result<Vec<u8>, String> {
    if stdin {
        let mut bytes = Vec::new();
        std::io::stdin()
            .read_to_end(&mut bytes)
            .map_err(|e| format!("cannot read stdin: {e}"))?;
        return Ok(bytes);
    }
    let path = path.ok_or("give a path or --stdin")?;
    std::fs::read(path).map_err(|e| {
        // A path can itself hold a known value.
        let shown = match Matcher::new(env_file.rules()) {
            Ok(matcher) => matcher.redact(&path.display().to_string()),
            Err(_) => "the given path".to_string(),
        };
        format!("cannot read {shown}: {e}")
    })
}

fn write_output(bytes: &[u8]) -> Exit {
    let mut stdout = std::io::stdout().lock();
    match stdout.write_all(bytes).and_then(|()| stdout.flush()) {
        Ok(()) => Exit::Clean,
        Err(e) => fail(&format!("cannot write stdout: {e}")),
    }
}

fn fail(message: &str) -> Exit {
    eprintln!("envscan: {message}");
    Exit::Error
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::Rule;

    fn filled(text: &str, pairs: &[(&str, &str)]) -> Filled {
        let listed = pairs.iter().map(|(k, _)| k.to_string()).collect();
        let values = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        fill(text.as_bytes(), &listed, &values)
    }

    fn text(f: &Filled) -> &str {
        std::str::from_utf8(&f.text).unwrap()
    }

    fn matcher(pairs: &[(&str, &str)]) -> Matcher {
        let rules = pairs
            .iter()
            .map(|(k, v)| Rule { value: v.to_string(), keys: vec![k.to_string()] })
            .collect();
        Matcher::new(rules).unwrap()
    }

    fn replaced(input: &str, pairs: &[(&str, &str)]) -> String {
        String::from_utf8(replace_values(input.as_bytes(), &matcher(pairs))).unwrap()
    }

    #[test]
    fn fills_both_forms_and_passes_every_other_shape() {
        let f = filled("$KEY ${KEY}s/$KEY.md", &[("KEY", "zqx")]);
        assert_eq!(text(&f), "zqx zqxs/zqx.md");
        for same in [
            "$HOME", "${HOME}", "$1", "$", "$$", "${KEY", "${KEY:-x}", "$(KEY)", "$KEY_B", "$KEYS",
            "$key", "{{KEY}}", "KEY",
        ] {
            assert_eq!(text(&filled(same, &[("KEY", "zqx")])), same);
        }
    }

    #[test]
    fn a_value_holding_a_reference_is_not_filled_again() {
        assert_eq!(text(&filled("$A", &[("A", "$B"), ("B", "zqx")])), "$B");
    }

    #[test]
    fn reports_used_and_missing_once_each_in_order() {
        let f = filled("$B $A $B $C $C", &[("A", "zqx"), ("B", ""), ("C", ""), ("D", "unused")]);
        assert_eq!(f.used, ["B", "A", "C"]);
        assert_eq!(f.missing, ["B", "C"]);
    }

    #[test]
    fn bytes_that_are_not_utf8_survive() {
        let listed = HashSet::from(["A".to_string()]);
        let values = HashMap::from([("A".to_string(), "zqx".to_string())]);
        assert_eq!(fill(b"\xff$A\xfe", &listed, &values).text, b"\xffzqx\xfe");
    }

    #[test]
    fn longest_value_wins_even_when_a_shorter_one_starts_first() {
        let pairs = [("SHORT", "zqx one"), ("LONG", "one two three")];
        assert_eq!(replaced("zqx one two three", &pairs), "zqx $LONG");
        let nested = [("SHORT", "zqxvalue"), ("LONG", "zqxvalue-corp")];
        assert_eq!(replaced("a/zqxvalue-corp/b zqxvalue", &nested), "a/$LONG/b $SHORT");
    }

    #[test]
    fn whole_words_only_with_underscore_as_a_word_character() {
        let pairs = [("KEY", "zqxvalue")];
        for same in ["zqxvalues", "azqxvalue", "pre_zqxvalue", "zqxvalue_post", "zqxvalue9"] {
            assert_eq!(replaced(same, &pairs), same);
        }
        assert_eq!(replaced("gs://zqxvalue-raw", &pairs), "gs://$KEY-raw");
    }

    #[test]
    fn braces_only_where_a_word_character_follows() {
        // Only a value with a non-word edge can match with a word character after it.
        let pairs = [("KEY", "/opt/zqx/")];
        assert_eq!(replaced("/opt/zqx/a", &pairs), "${KEY}a");
        assert_eq!(replaced("/opt/zqx/.a", &pairs), "$KEY.a");
        assert_eq!(replaced("/opt/zqx/", &pairs), "$KEY");
    }

    #[test]
    fn a_case_variant_is_replaced_as_the_scanner_would_flag_it() {
        assert_eq!(replaced("ZQXVALUE", &[("KEY", "zqxvalue")]), "$KEY");
    }

    #[test]
    fn a_variable_name_equal_to_a_value_is_left_alone() {
        let pairs = [("KEY", "home")];
        assert_eq!(replaced("$HOME ${HOME} $home home", &pairs), "$HOME ${HOME} $home $KEY");
    }

    #[test]
    fn a_value_spanning_a_reference_is_still_replaced() {
        assert_eq!(replaced("$HOME/zqx", &[("KEY", "$HOME/zqx")]), "$KEY");
    }
}
