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
    /// Record how `tmp/` files were handled, and decide whether a topic folder can be cleared.
    Promotion(crate::promotion::PromotionArgs),
    /// Save machine-wide settings.
    Config(ConfigArgs),
    /// The outbound gate. Reads a PreToolUse hook's JSON on stdin; with --pre-push, git's
    /// pre-push lines. Exit 0 allow, 2 deny with the reason on stderr naming keys only,
    /// 3 usage or IO error. `gate install` writes the repo's pre-push hook.
    Gate(crate::gate::GateArgs),
}

#[derive(Args, Debug)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Save the judgement tier. Live also needs a key; auto and unset run plain with a reminder.
    Tier {
        #[arg(value_enum)]
        tier: TierChoice,
    },
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub enum TierChoice {
    Auto,
    Live,
    Plain,
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
    /// Under the live tier, the whole-run limit: over it nothing is sent, after printing the
    /// estimate.
    #[arg(long, value_name = "N", default_value_t = crate::judge::DEFAULT_MAX_CANDIDATES)]
    pub max_candidates: usize,
    /// Under the live tier, a file with more candidates than this sends nothing and lists them
    /// as unjudged. The rest of the run proceeds.
    #[arg(long, value_name = "N", default_value_t = crate::judge::DEFAULT_MAX_FILE_CANDIDATES)]
    pub max_file_candidates: usize,
}
