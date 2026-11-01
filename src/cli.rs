//! Argument parsing. Add a subcommand by adding a `Command` variant.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "envscan", version, about = "Find known and likely sensitive values in text")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Scan paths for known values. Exit 0 clean, 1 leaks, 2 no rules, 3 usage or IO error,
    /// nothing scanned, or a data file left unscanned.
    Scan(ScanArgs),
    /// Fill each listed $KEY from `.env` and print the text. Never writes in place. Exit 0
    /// resolved, 2 a listed key has no value or no key list exists, 3 usage or IO error.
    Hydrate(HydrateArgs),
    /// Replace known values with $KEY and print the text. Exit 0 done, 2 no known values,
    /// 3 usage or IO error.
    Dehydrate(DehydrateArgs),
}

#[derive(Args, Debug)]
pub struct HydrateArgs {
    /// The text to read. Give this or --stdin.
    #[arg(required_unless_present = "stdin", conflicts_with = "stdin")]
    pub path: Option<PathBuf>,
    /// Read the text from standard input.
    #[arg(long)]
    pub stdin: bool,
    /// The values file; defaults to `.env` at the repo root. Keys are also read from the
    /// `.env.example` beside it.
    #[arg(long, value_name = "FILE")]
    pub env: Option<PathBuf>,
    /// Only report whether every key in the text resolves, printing key names and no values.
    #[arg(long)]
    pub check: bool,
}

#[derive(Args, Debug)]
pub struct DehydrateArgs {
    /// The text to read. Give this or --stdin.
    #[arg(required_unless_present = "stdin", conflicts_with = "stdin")]
    pub path: Option<PathBuf>,
    /// Read the text from standard input.
    #[arg(long)]
    pub stdin: bool,
    /// The values file; defaults to `.env` at the repo root.
    #[arg(long, value_name = "FILE")]
    pub env: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Files or directories; defaults to the current directory unless --stdin is given.
    pub paths: Vec<PathBuf>,
    /// The rules file; defaults to `.env` at the repo root.
    #[arg(long, value_name = "FILE")]
    pub env: Option<PathBuf>,
    /// List every location unmasked. For the local agent only, never a post.
    #[arg(long)]
    pub full: bool,
    /// Match known values only, with no broad extraction.
    #[arg(long)]
    pub known_only: bool,
    /// Also scan standard input.
    #[arg(long)]
    pub stdin: bool,
    /// Print the report as JSON.
    #[arg(long)]
    pub json: bool,
    /// How many candidates to list.
    #[arg(long, value_name = "N", default_value_t = 20)]
    pub top: usize,
    /// Do not apply ignore rules or prune generated directories. `.git`, `.env` and
    /// secret-named files stay excluded.
    #[arg(long)]
    pub no_ignore: bool,
}
