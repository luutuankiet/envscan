//! What is in scope for a scan.
//!
//! Scope is the walk root's own ignore rules and below: rules above the root do not apply,
//! so naming `tmp/topic` as the root scans it even when the repo ignores `tmp/`, and scanning
//! the repo root prunes that same `tmp/`. Promotion therefore passes the topic folder.
//!
//! Accepted gap: an outer rule also applies inside a nested repo below the root, hiding a
//! file that repo's own git would not ignore. `require_git(false)` causes it, and is what lets
//! a topic folder that is not a repo honour its `.gitignore`. `--no-ignore` sees past it.

use ignore::WalkBuilder;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Directories holding only regenerated content. Names such as `build` or `vendor` are left
/// out on purpose, because a tree can commit authored text under them.
const GENERATED_DIRS: &[&str] = &[
    "node_modules", "bower_components", ".venv", "venv", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".tox", "site-packages", ".next", ".nuxt", ".turbo", ".cache",
    ".gradle", ".terraform",
];

/// `.env` and key material by name, ignoring case. The example forms are committed by design,
/// so a value in one is a real leak and they stay in scope.
pub fn is_secret_name(name: &str) -> bool {
    let n = name.to_lowercase();
    if matches!(n.as_str(), ".env.example" | ".env.sample" | ".env.template") {
        return false;
    }
    n == ".env"
        || n.starts_with(".env.")
        || [".env", ".pem", ".key", ".p12", ".pfx", ".credentials.json"].iter().any(|s| n.ends_with(s))
        || n == "credentials.json"
        || n.starts_with("id_rsa")
        || n.starts_with("id_ed25519")
        || n.starts_with("client_secret")
}

pub struct Options {
    pub no_ignore: bool,
    /// The rules file, excluded whatever it is called.
    pub rules_file: Option<PathBuf>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Item {
    pub path: PathBuf,
    /// Relative to the working directory when under it, else to the root's parent. An
    /// absolute root must not print a home path.
    pub display: String,
    pub name: String,
    pub is_file: bool,
}

#[derive(Debug, Default)]
pub struct Walk {
    /// Files and directories below the roots, sorted by display path. A root directory's own
    /// name is the caller's, so it is not listed; a root file is.
    pub items: Vec<Item>,
    pub secret_named: usize,
    pub errors: Vec<String>,
}

pub fn walk(roots: &[PathBuf], cwd: &Path, options: &Options) -> Walk {
    let mut out = Walk::default();
    let rules_file = options.rules_file.as_ref().and_then(|p| p.canonicalize().ok());
    let cwd_real = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
    let mut seen = HashSet::new();
    for root in roots {
        let Ok(root_real) = cwd.join(root).canonicalize() else {
            out.errors.push(format!("cannot read {}", root.display()));
            continue;
        };
        // A symlink named as a root is the caller's choice, and the walker would not enter it.
        let mut builder = WalkBuilder::new(&root_real);
        let no_ignore = options.no_ignore;
        builder
            .hidden(false)
            .parents(false)
            .ignore(false)
            .git_global(false)
            .git_exclude(!no_ignore)
            .git_ignore(!no_ignore)
            .require_git(false)
            .filter_entry(move |e| {
                let name = e.file_name().to_str().unwrap_or("");
                // `.git` is a file in a linked worktree, and it holds an absolute path.
                if e.depth() > 0 && name == ".git" {
                    return false;
                }
                let is_dir = e.file_type().is_some_and(|t| t.is_dir());
                no_ignore || !is_dir || !GENERATED_DIRS.contains(&name)
            });
        for entry in builder.build() {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    out.errors.push(e.to_string());
                    continue;
                }
            };
            let Some(kind) = entry.file_type() else { continue };
            let is_dir = kind.is_dir();
            if (!is_dir && !kind.is_file()) || (is_dir && entry.depth() == 0) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if !is_dir {
                let is_rules_file = rules_file.as_ref().is_some_and(|rules| {
                    rules.file_name() == Some(entry.file_name())
                        && entry.path().canonicalize().ok().as_ref() == Some(rules)
                });
                if is_secret_name(&name) || is_rules_file {
                    out.secret_named += 1;
                    continue;
                }
            }
            if !seen.insert(entry.path().to_path_buf()) {
                continue;
            }
            let display = display_path(entry.path(), &root_real, &cwd_real);
            out.items.push(Item { path: entry.into_path(), display, name, is_file: !is_dir });
        }
    }
    out.items.sort_by(|a, b| a.display.cmp(&b.display));
    out
}

fn display_path(path: &Path, root: &Path, cwd: &Path) -> String {
    if let Ok(rel) = path.strip_prefix(cwd) {
        return rel.display().to_string();
    }
    let base = root.parent().unwrap_or(root);
    path.strip_prefix(base).unwrap_or(path).display().to_string()
}

#[cfg(test)]
mod tests {
    use super::is_secret_name;

    #[test]
    fn secret_names() {
        for name in [".env", ".ENV", ".env.local", "prod.env", "a.pem", "a.KEY", "a.p12", "a.pfx",
            "id_rsa", "id_rsa.pub", "id_ed25519", "client_secret_1.json", "credentials.json",
            "x.credentials.json"] {
            assert!(is_secret_name(name), "{name}");
        }
        for name in [".env.example", ".env.sample", ".env.template", "environment.md", "key.md",
            "keyboard.txt", "notes.txt"] {
            assert!(!is_secret_name(name), "{name}");
        }
    }
}
