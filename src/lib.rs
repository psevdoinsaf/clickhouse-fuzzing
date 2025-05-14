use std::path::Path;
use anyhow::Result;

pub mod fuzzer;
pub mod mutations;

pub use fuzzer::ClickHouseFuzzer;

#[derive(Debug)]
pub struct FuzzingStats {
    pub total_executions: u64,
    pub unique_crashes: u32,
    pub coverage_blocks: usize,
}

#[derive(Debug)]
pub enum ExecutionResult {
    Ok,
    Crash(String),
    Timeout,
    MemoryLimit,
}

pub trait FuzzTarget {
    fn load_corpus<P: AsRef<Path>>(&self, path: P) -> Result<Vec<Vec<u8>>>;

    fn run<P: AsRef<Path>>(
        &mut self,
        corpus: Vec<Vec<u8>>,
        output_dir: P,
        mem_limit: usize,
        time_limit: u64,
    ) -> Result<FuzzingStats>;
}

pub use snapchange::{
    addrs::{Cr3, VirtAddr},
    fuzzer::{Breakpoint, BreakpointLookup, BreakpointType, Fuzzer},
    fuzzvm::FuzzVm,
    Execution,
};
