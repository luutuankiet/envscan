//! Known-value matching. Case-insensitive, with two boundary tiers.
//!
//! Strict: neither neighbour is a word character, `-`, or (before the value) `.`.
//! Loose: a `-` on either side or a leading `.`, so `gs://value-raw` and `sub.value` match.
//! `_` stays a word character, so `pre_value` does not match, in line with the whole-word
//! rule `dehydrate` rewrites by. A non-ASCII neighbour counts as a boundary, because text
//! with no spaces between words must not hide a value. Side checks apply only where the
//! value's own edge is a word character: `/opt/value` still matches inside `mnt/opt/value`.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::bytes::Regex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub value: String,
    pub keys: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hit {
    pub rule: usize,
    pub start: usize,
    pub end: usize,
    pub strict: bool,
}

pub struct Matcher {
    rules: Vec<Rule>,
    /// ASCII values, which aho-corasick can fold. Index into `rules` by pattern id.
    ascii: Option<AhoCorasick>,
    ascii_rules: Vec<usize>,
    /// aho-corasick folds ASCII only, so a non-ASCII value gets a regex to fold its case.
    unicode: Vec<(usize, Regex)>,
}

pub(crate) fn word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// `None` when this occurrence is inside a longer word, else whether it is strict.
fn classify(value: &[u8], hay: &[u8], start: usize, end: usize) -> Option<bool> {
    let before = start.checked_sub(1).map(|i| hay[i]);
    let after = hay.get(end).copied();
    let first_is_word = value.first().is_some_and(|b| word(*b));
    let last_is_word = value.last().is_some_and(|b| word(*b));
    if (first_is_word && before.is_some_and(word)) || (last_is_word && after.is_some_and(word)) {
        return None;
    }
    let loose = (first_is_word && matches!(before, Some(b'-' | b'.')))
        || (last_is_word && after == Some(b'-'));
    Some(!loose)
}

impl Matcher {
    pub fn new(rules: Vec<Rule>) -> Result<Matcher, String> {
        let mut ascii_rules = Vec::new();
        let mut unicode = Vec::new();
        for (i, rule) in rules.iter().enumerate() {
            if rule.value.is_ascii() {
                ascii_rules.push(i);
            } else {
                let pattern = format!("(?i){}", regex::escape(&rule.value));
                let re = Regex::new(&pattern).map_err(|e| e.to_string())?;
                unicode.push((i, re));
            }
        }
        let ascii = if ascii_rules.is_empty() {
            None
        } else {
            let values = ascii_rules.iter().map(|i| rules[*i].value.as_str());
            let built = AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .match_kind(MatchKind::Standard)
                .build(values)
                .map_err(|e| e.to_string())?;
            Some(built)
        };
        Ok(Matcher { rules, ascii, ascii_rules, unicode })
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Every bounded occurrence, ordered by position.
    pub fn find(&self, hay: &[u8]) -> Vec<Hit> {
        let mut hits = Vec::new();
        if let Some(ac) = &self.ascii {
            for m in ac.find_overlapping_iter(hay) {
                let rule = self.ascii_rules[m.pattern().as_usize()];
                self.push(&mut hits, hay, rule, m.start(), m.end());
            }
        }
        for (rule, re) in &self.unicode {
            for m in re.find_iter(hay) {
                self.push(&mut hits, hay, *rule, m.start(), m.end());
            }
        }
        hits.sort_by_key(|h| (h.start, h.end, h.rule));
        hits
    }

    fn push(&self, hits: &mut Vec<Hit>, hay: &[u8], rule: usize, start: usize, end: usize) {
        if let Some(strict) = classify(self.rules[rule].value.as_bytes(), hay, start, end) {
            hits.push(Hit { rule, start, end, strict });
        }
    }

    /// Replace each hit with its key. A path in a report can itself hold a known value, and a
    /// report never contains a value outside `--full`.
    pub fn redact(&self, text: &str) -> String {
        let mut hits = self.find(text.as_bytes());
        hits.sort_by_key(|h| (h.start, std::cmp::Reverse(h.end)));
        let mut out = String::with_capacity(text.len());
        let mut at = 0;
        for hit in hits {
            if hit.start < at {
                continue;
            }
            out.push_str(&text[at..hit.start]);
            let key = &self.rules[hit.rule].keys[0];
            if text.as_bytes().get(hit.end).is_some_and(|b| word(*b)) {
                out.push_str(&format!("${{{key}}}"));
            } else {
                out.push_str(&format!("${key}"));
            }
            at = hit.end;
        }
        out.push_str(&text[at..]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher(values: &[&str]) -> Matcher {
        let rules = values
            .iter()
            .enumerate()
            .map(|(i, v)| Rule { value: v.to_string(), keys: vec![format!("KEY_{i}")] })
            .collect();
        Matcher::new(rules).unwrap()
    }

    /// (strict hits, loose hits)
    fn tiers(m: &Matcher, hay: &str) -> (usize, usize) {
        let hits = m.find(hay.as_bytes());
        let strict = hits.iter().filter(|h| h.strict).count();
        (strict, hits.len() - strict)
    }

    #[test]
    fn boundary_table() {
        let m = matcher(&["zqxvalue"]);
        for (hay, want) in [
            ("zqxvalue", (1, 0)),
            ("a zqxvalue b", (1, 0)),
            ("end of zqxvalue.", (1, 0)),
            ("/srv/zqxvalue/x", (1, 0)),
            ("ZQXVALUE", (1, 0)),
            ("ZqXvAlUe", (1, 0)),
            ("gs://zqxvalue-raw", (0, 1)),
            ("pre-zqxvalue", (0, 1)),
            ("sub.zqxvalue", (0, 1)),
            ("zqxvalues", (0, 0)),
            ("azqxvalue", (0, 0)),
            ("pre_zqxvalue", (0, 0)),
            ("zqxvalue_post", (0, 0)),
            ("zqxvalue9", (0, 0)),
            ("zqxvalue zqxvalue-x", (1, 1)),
        ] {
            assert_eq!(tiers(&m, hay), want, "{hay}");
        }
    }

    #[test]
    fn a_subdomain_of_a_known_domain_is_a_loose_hit() {
        let m = matcher(&["zqxvalue.example"]);
        assert_eq!(tiers(&m, "https://zqxvalue.example/x"), (1, 0));
        assert_eq!(tiers(&m, "https://hooks.zqxvalue.example/x"), (0, 1));
    }

    #[test]
    fn a_non_ascii_neighbour_is_a_boundary() {
        let m = matcher(&["zqxvalue"]);
        assert_eq!(tiers(&m, "日本zqxvalue語"), (1, 0));
    }

    #[test]
    fn non_ascii_values_fold_case() {
        let m = matcher(&["zqxmüller"]);
        assert_eq!(tiers(&m, "the ZQXMÜLLER file"), (1, 0));
        assert_eq!(tiers(&m, "pre-zqxmüller"), (0, 1));
        assert_eq!(tiers(&m, "zqxmüllers"), (0, 0));
    }

    #[test]
    fn a_value_with_a_non_word_edge_has_no_boundary_on_that_side() {
        let m = matcher(&["/opt/zqxvalue"]);
        assert_eq!(tiers(&m, "mnt/opt/zqxvalue/x"), (1, 0));
        assert_eq!(tiers(&m, "mnt/opt/zqxvalues"), (0, 0));
    }

    #[test]
    fn overlapping_values_both_hit() {
        let m = matcher(&["zqxvalue", "zqxvalue-corp"]);
        let rules: Vec<usize> = m.find(b"zqxvalue-corp").iter().map(|h| h.rule).collect();
        assert_eq!(rules.len(), 2);
        assert!(rules.contains(&0) && rules.contains(&1));
    }

    #[test]
    fn redact_prefers_the_longest_and_leaves_other_text() {
        let m = matcher(&["zqxvalue", "zqxvalue-corp"]);
        assert_eq!(m.redact("dir/zqxvalue-corp/a.md"), "dir/$KEY_1/a.md");
        assert_eq!(m.redact("zqxvalue.md"), "$KEY_0.md");
        assert_eq!(m.redact("zqxvalues.md"), "zqxvalues.md");
    }
}
