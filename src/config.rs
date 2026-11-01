//! The machine-wide judgement tier and the vendor key. `~/.config/envscan/config.toml` holds the
//! tier; the key comes from the process environment, then `~/.config/envscan/env`, which is
//! parsed and never sourced. A repo `.env` is never read for it: every value there is blocked text.

use crate::cli::{ConfigArgs, ConfigCommand, TierChoice};
use crate::exit::Exit;
use std::path::PathBuf;

const KEY_NAME: &str = "TYPESAFE_API_KEY";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Saved {
    /// Nothing saved, or `auto`: plain with one reminder line.
    Unset,
    Live,
    Plain,
    /// The file exists and cannot be understood. Runs as unset, and the caller says so.
    Bad,
}

fn dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").filter(|h| !h.is_empty())?;
    Some(PathBuf::from(home).join(".config/envscan"))
}

pub fn saved_tier() -> Saved {
    let Some(path) = dir().map(|d| d.join("config.toml")) else { return Saved::Unset };
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Saved::Unset,
        Err(_) => return Saved::Bad,
    };
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#'));
    let tier = lines.next().and_then(|l| l.split_once('=')).filter(|(k, _)| k.trim() == "tier");
    match tier.map(|(_, v)| v.trim().trim_matches('"')) {
        Some("live") => Saved::Live,
        Some("plain") => Saved::Plain,
        Some("auto") => Saved::Unset,
        _ => Saved::Bad,
    }
}

/// The key, or a fixed reason that holds no part of it.
pub fn api_key() -> Result<String, &'static str> {
    if let Some(key) = std::env::var(KEY_NAME).ok().filter(|k| !k.trim().is_empty()) {
        return Ok(key.trim().to_string());
    }
    let path = dir().ok_or("no key")?.join("env");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(_) => return Err("no key"),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).map_err(|_| "no key")?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err("key file readable by others");
        }
    }
    for line in text.lines() {
        let line = line.trim();
        let line = line.strip_prefix("export ").unwrap_or(line);
        if let Some((name, value)) = line.split_once('=') {
            let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
            if name.trim() == KEY_NAME && !value.is_empty() {
                return Ok(value.to_string());
            }
        }
    }
    Err("no key")
}

pub fn run(args: &ConfigArgs) -> Exit {
    let ConfigCommand::Tier { tier } = &args.command;
    let value = match tier {
        TierChoice::Auto => "auto",
        TierChoice::Live => "live",
        TierChoice::Plain => "plain",
    };
    let Some(dir) = dir() else {
        eprintln!("envscan: HOME is not set, so there is nowhere to save the tier");
        return Exit::Error;
    };
    // A rename, so a concurrent reader sees the old file or the new one.
    let tmp = dir.join(format!("config.toml.{}", std::process::id()));
    let written = std::fs::create_dir_all(&dir)
        .and_then(|_| std::fs::write(&tmp, format!("tier = \"{value}\"\n")))
        .and_then(|_| std::fs::rename(&tmp, dir.join("config.toml")));
    match written {
        Ok(()) => {
            println!("tier: {value}");
            Exit::Clean
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            eprintln!("envscan: cannot save the tier: {}", e.kind());
            Exit::Error
        }
    }
}
