use anyhow::Result;
use clap::Parser;
use log::{info, warn};
use std::path::PathBuf;
use std::time::Duration;

use clickhouse_fuzzer::ClickHouseFuzzer;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, default_value = "corpus")]
    corpus: PathBuf,
    #[clap(short, long, default_value = "crashes")]
    output: PathBuf,
    #[clap(short, long, default_value = "8192")]
    mem_limit: usize,
    #[clap(short, long, default_value = "0")]
    time_limit: u64,
    #[clap(long, default_value = "clickhouse")]
    snapshot: String,
}

fn main() -> Result<()> {
    let args = Args::parse();    
    if !args.output.exists() {
        std::fs::create_dir_all(&args.output)?;
    }

    let mut fuzzer = ClickHouseFuzzer::default();

    let corpus = match fuzzer.load_corpus(&args.corpus) {
        Ok(corpus) => {
            corpus
        }
        Err(e) => {
            warn!("Error while loading corpus: {}", e);
            Vec::new()
        }
    };

    match fuzzer.run(
        corpus,
        &args.output,
        args.mem_limit * 1024 * 1024,
        args.time_limit,
    ) {
        Ok(stats) => {
            info!("executions: {}", stats.total_executions);
            info!("crashes: {}", stats.unique_crashes);
        }
        Err(e) => {
            warn!("Error while fuzzing: {}", e);
        }
    }

    Ok(())
}