//! envscan: find known and likely sensitive values in text before it leaves a machine.
//!
//! `cli` parses, `env` finds and reads the `.env`, `matcher` holds the known-value rules,
//! `walker` decides what is in scope, `extract` finds broad candidates, `data` streams data files, `scan` runs them, `report` is the output shape.
//! `hydrate` moves text between `$KEY` and real values.
//! `promotion` keeps the record of what left `tmp/` and decides whether a folder can be cleared.
//! `config` holds the judgement tier and key, `judge` the vendor call.
//! Each later subcommand is a variant of `cli::Command` plus its own module.

pub mod cli;
pub mod config;
pub mod data;
pub mod env;
pub mod exit;
pub mod extract;
pub mod hydrate;
pub mod judge;
pub mod matcher;
pub mod promotion;
pub mod report;
pub mod scan;
pub mod walker;

use clap::Parser;
use exit::Exit;

pub fn run() -> Exit {
    let cli = match cli::Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            // clap exits 2 for a usage error, which here would mean "no rules loaded".
            return if e.use_stderr() { Exit::Error } else { Exit::Clean };
        }
    };
    match cli.command {
        cli::Command::Scan(args) => scan::run(&args),
        cli::Command::Hydrate(args) => hydrate::run_hydrate(&args),
        cli::Command::Dehydrate(args) => hydrate::run_dehydrate(&args),
        cli::Command::Promotion(args) => promotion::run(&args),
        cli::Command::Config(args) => config::run(&args),
    }
}
