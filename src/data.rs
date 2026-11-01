//! Data files: text forms are streamed through known-value matching with no size cap and no
//! extractor; every other form is only listed. Nothing here parses a row or reads a header.

use crate::matcher::Matcher;
use std::collections::BTreeMap;
use std::io::{self, Read};

/// Memory per file stays near this, whatever the file's size.
const CHUNK_BYTES: usize = 1 << 20;
const SNIFF_BYTES: usize = 8192;

/// What one rule hit in one stream.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RuleHits {
    pub strict: usize,
    pub loose: usize,
    /// Distinct line numbers in order, up to the caller's limit.
    pub lines: Vec<usize>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Streamed {
    Scanned(BTreeMap<usize, RuleHits>),
    /// A NUL near the start, as in UTF-16: matching these bytes would find nothing and prove
    /// nothing, so it is listed as unscanned instead.
    NotText,
}

pub fn stream(matcher: &Matcher, reader: impl Read, max_lines: usize) -> io::Result<Streamed> {
    stream_chunks(matcher, reader, max_lines, CHUNK_BYTES)
}

/// Each pass matches the kept tail plus a new chunk. A hit is settled once the byte after it is
/// in the buffer, and the tail is long enough to hold any match unsettled by the last pass plus
/// the byte before it, so a value across a chunk edge is counted once with both neighbours seen.
fn stream_chunks(
    matcher: &Matcher,
    mut reader: impl Read,
    max_lines: usize,
    chunk: usize,
) -> io::Result<Streamed> {
    let keep = matcher.max_match_bytes() + 1;
    let mut by_rule: BTreeMap<usize, RuleHits> = BTreeMap::new();
    let mut buf: Vec<u8> = Vec::with_capacity(chunk + keep);
    // Bytes before `buf`, its first line, and how far the last pass settled.
    let (mut base, mut base_line, mut settled) = (0u64, 1usize, 0u64);
    let mut first = true;
    loop {
        let before = buf.len();
        let got = reader.by_ref().take(chunk as u64).read_to_end(&mut buf)?;
        let eof = got < chunk;
        if first && memchr::memchr(0, &buf[before..buf.len().min(SNIFF_BYTES)]).is_some() {
            return Ok(Streamed::NotText);
        }
        first = false;

        let (mut cursor, mut line) = (0, base_line);
        for hit in matcher.find(&buf) {
            line += memchr::memchr_iter(b'\n', &buf[cursor..hit.start]).count();
            cursor = hit.start;
            if base + (hit.end as u64) < settled || (!eof && hit.end == buf.len()) {
                continue;
            }
            let hits = by_rule.entry(hit.rule).or_default();
            if hit.strict { hits.strict += 1 } else { hits.loose += 1 }
            if hits.lines.len() < max_lines && hits.lines.last() != Some(&line) {
                hits.lines.push(line);
            }
        }
        if eof {
            return Ok(Streamed::Scanned(by_rule));
        }

        settled = base + buf.len() as u64;
        let drop = buf.len().saturating_sub(keep);
        base_line += memchr::memchr_iter(b'\n', &buf[..drop]).count();
        base += drop as u64;
        buf.drain(..drop);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::Rule;

    fn matcher(values: &[&str]) -> Matcher {
        let rules = values
            .iter()
            .enumerate()
            .map(|(i, v)| Rule { value: v.to_string(), keys: vec![format!("KEY_{i}")] })
            .collect();
        Matcher::new(rules).unwrap()
    }

    fn whole(m: &Matcher, text: &[u8]) -> BTreeMap<usize, RuleHits> {
        let mut want: BTreeMap<usize, RuleHits> = BTreeMap::new();
        for hit in m.find(text) {
            let line = memchr::memchr_iter(b'\n', &text[..hit.start]).count() + 1;
            let hits = want.entry(hit.rule).or_default();
            if hit.strict { hits.strict += 1 } else { hits.loose += 1 }
            if hits.lines.last() != Some(&line) {
                hits.lines.push(line);
            }
        }
        want
    }

    /// Every chunk edge, so a value and each of its neighbours fall on one somewhere.
    #[test]
    fn any_chunk_size_finds_what_one_buffer_finds() {
        let m = matcher(&["zqxvalue", "zqxvalue-corp", "zqxmüller"]);
        let text = "a,zqxvalue\nzqxvalues,azqxvalue\nsub.zqxvalue,\n\nzqxvalue-corp\nthe ZQXMÜLLER x\nzqxvalue".as_bytes();
        let want = whole(&m, text);
        assert_eq!(want[&0].strict + want[&0].loose, 4);
        for chunk in 1..=text.len() + 1 {
            match stream_chunks(&m, text, usize::MAX, chunk).unwrap() {
                Streamed::Scanned(got) => assert_eq!(got, want, "chunk {chunk}"),
                Streamed::NotText => panic!("chunk {chunk}"),
            }
        }
    }

    #[test]
    fn a_word_continuing_past_a_chunk_edge_is_not_a_hit() {
        let m = matcher(&["zqxvalue"]);
        for chunk in 1..=12 {
            match stream_chunks(&m, &b"zqxvalues"[..], usize::MAX, chunk).unwrap() {
                Streamed::Scanned(got) => assert!(got.is_empty(), "chunk {chunk}"),
                Streamed::NotText => panic!(),
            }
        }
    }

    #[test]
    fn a_nul_near_the_start_is_not_text_and_a_late_one_is_only_bytes() {
        let m = matcher(&["zqxvalue"]);
        assert_eq!(stream(&m, &b"a\0zqxvalue"[..], 3).unwrap(), Streamed::NotText);
        let mut late = vec![b'x'; SNIFF_BYTES];
        late.extend_from_slice(b"\0 zqxvalue");
        match stream(&m, &late[..], 3).unwrap() {
            Streamed::Scanned(got) => assert_eq!(got[&0].strict, 1),
            Streamed::NotText => panic!(),
        }
    }

    #[test]
    fn bytes_that_are_not_utf8_still_match() {
        let m = matcher(&["zqxvalue"]);
        match stream(&m, &b"caf\xe9,zqxvalue\n"[..], 3).unwrap() {
            Streamed::Scanned(got) => assert_eq!(got[&0].lines, [1]),
            Streamed::NotText => panic!(),
        }
    }
}
