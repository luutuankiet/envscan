//! The scan report. The field order and key names are a contract for `--json` readers.

use serde::Serialize;
use std::collections::BTreeMap;

/// Unscanned files listed in the text form; a tree can hold thousands.
const TEXT_DATA_CAP: usize = 20;

#[derive(Serialize, Debug, Default)]
pub struct Report {
    pub tier: String,
    pub rules_loaded: usize,
    pub short_values: Vec<String>,
    pub env_unparsed_lines: Vec<usize>,
    pub files_scanned: usize,
    pub skipped: Skipped,
    pub extractor_errors: usize,
    pub leaks: Vec<Leak>,
    pub data_files: Vec<DataFile>,
    pub candidates_total: usize,
    pub candidates_by_kind: BTreeMap<String, usize>,
    pub candidates: Vec<Candidate>,
    /// Lists every data file in the text form too, as `--full` does for everything else.
    #[serde(skip)]
    pub full: bool,
}

#[derive(Serialize, Debug, Default)]
pub struct Skipped {
    pub large: usize,
    pub binary: usize,
    pub non_utf8: usize,
    pub secret_named: usize,
    pub long_lines: usize,
}

#[derive(Serialize, Debug, Default, Clone)]
pub struct Leak {
    pub key: String,
    pub strict: usize,
    pub loose: usize,
    /// `path:line`, or `path` for a hit in a name.
    pub at: Vec<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct DataFile {
    pub path: String,
    /// The lowercase extension.
    pub format: String,
    /// The size. Never rows or columns, which would mean reading a header.
    pub shape: String,
    pub scanned: bool,
}

#[derive(Serialize, Debug, Clone)]
pub struct Candidate {
    pub kind: String,
    pub masked: String,
    pub files: usize,
    pub hits: usize,
    pub first: String,
    /// The real value and every location, under `--full` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub at: Vec<String>,
}

impl Report {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("the report is plain data")
    }

    /// Leaks by key, never by value.
    pub fn to_text(&self) -> String {
        let mut out = format!("tier: {}\n", self.tier);
        let s = &self.skipped;
        out.push_str(&format!(
            "rules loaded: {}   files scanned: {}   skipped: {} large, {} binary, {} non-utf8, {} secret-named, {} long lines\n",
            self.rules_loaded, self.files_scanned, s.large, s.binary, s.non_utf8, s.secret_named, s.long_lines
        ));
        if !self.short_values.is_empty() {
            out.push_str(&format!("short values, not matched: {}\n", self.short_values.join(", ")));
        }
        if !self.env_unparsed_lines.is_empty() {
            let lines: Vec<String> = self.env_unparsed_lines.iter().map(|n| n.to_string()).collect();
            out.push_str(&format!(".env lines not parsed: {}\n", lines.join(", ")));
        }
        let hits: usize = self.leaks.iter().map(|l| l.strict + l.loose).sum();
        out.push_str(&format!("\nLEAKS  {hits} hits across {} keys (write as $KEY)\n", self.leaks.len()));
        for leak in &self.leaks {
            out.push_str(&format!(
                "  {:<20} strict {:>4}  loose {:>4}  {}\n",
                leak.key, leak.strict, leak.loose, leak.at.join("  ")
            ));
        }
        self.push_data_files(&mut out);
        if self.extractor_errors > 0 {
            out.push_str(&format!(
                "\nEXTRACTOR ERRORS  {}: those lines may hold more candidates than listed\n",
                self.extractor_errors
            ));
        }
        self.push_candidates(&mut out);
        out
    }

    /// Unscanned first, because those are what stop this being a clean result.
    fn push_data_files(&self, out: &mut String) {
        if self.data_files.is_empty() {
            return;
        }
        let unscanned: Vec<&DataFile> = self.data_files.iter().filter(|d| !d.scanned).collect();
        let scanned = self.data_files.len() - unscanned.len();
        out.push_str(&format!(
            "\nDATA FILES  {} matched for known values, {} unscanned{}\n",
            scanned,
            unscanned.len(),
            if unscanned.is_empty() { "" } else { ": not a clean result" }
        ));
        let cap = if self.full { usize::MAX } else { TEXT_DATA_CAP };
        for d in unscanned.iter().take(cap) {
            out.push_str(&format!("  unscanned  {:<8} {:>14}  {}\n", d.format, d.shape, d.path));
        }
        if unscanned.len() > cap {
            out.push_str(&format!("  and {} more unscanned; --json lists them all\n", unscanned.len() - cap));
        }
    }

    fn push_candidates(&self, out: &mut String) {
        let by_kind: Vec<String> = self.candidates_by_kind.iter().map(|(k, n)| format!("{k} {n}")).collect();
        out.push_str(&format!("\nCANDIDATES  {} (top {} by weight, then spread)", self.candidates_total, self.candidates.len()));
        if !by_kind.is_empty() {
            out.push_str(&format!("  {}", by_kind.join(", ")));
        }
        out.push('\n');
        for c in &self.candidates {
            out.push_str(&format!(
                "  {:<12} {:<20} files {:>3}  hits {:>4}  {}\n",
                c.kind,
                c.value.as_deref().unwrap_or(&c.masked),
                c.files,
                c.hits,
                if c.at.is_empty() { c.first.clone() } else { c.at.join("  ") }
            ));
        }
    }
}
