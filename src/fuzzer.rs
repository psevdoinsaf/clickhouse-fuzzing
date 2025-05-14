use crate::{ExecutionResult, FuzzTarget, FuzzingStats};
use anyhow::Result;
use snapchange::addrs::{Cr3, VirtAddr};
use snapchange::fuzzer::{Breakpoint, BreakpointLookup, BreakpointType, Fuzzer};
use snapchange::fuzzvm::FuzzVm;
use snapchange::Execution;
use std::collections::HashSet;
use std::path::Path;
use std::time::Instant;

pub const CR3: Cr3 = Cr3(0x1234); // set real value
const SQL_PARSER_ENTRY: u64 = 0x4012B0; // set real value
const MAX_MEMORY_LIMIT: usize = 8589934592; // 8GB - mb change?

#[derive(Default)]
pub struct ClickHouseFuzzer {
    coverage: HashSet<u64>,
    crashes: HashSet<String>,
    execution_count: u64,
}

#[derive(Debug, PartialEq)]
enum ParserState {
    Starting,
    Parsing,
    Error,
    Completed,
}

impl FuzzTarget for ClickHouseFuzzer {
    fn load_corpus<P: AsRef<Path>>(&self, path: P) -> Result<Vec<Vec<u8>>> {
        let mut corpus = Vec::new();
        for entry in std::fs::read_dir(path)? {
            let path = entry?.path();
            corpus.push(std::fs::read(&path)?);
        }
        Ok(corpus)
    }

    fn run<P: AsRef<Path>>(
        &mut self,
        corpus: Vec<Vec<u8>>,
        output_dir: P,
        mem_limit: usize,
        time_limit: u64,
    ) -> Result<FuzzingStats> {
        let start_time = Instant::now();
        let mut vm = FuzzVm::new()?;

        for input in corpus {
            if time_limit > 0 && start_time.elapsed().as_secs() >= time_limit {
                break;
            }

            match self.execute_input(&mut vm, &input) {
                ExecutionResult::Crash(crash_info) => {
                    self.handle_crash(&output_dir, &input, &crash_info)?;
                }
                ExecutionResult::Ok => {}
            }
        }

        Ok(FuzzingStats {
            total_executions: self.execution_count,
            unique_crashes: self.crashes.len() as u32,
            coverage_blocks: self.coverage.len(),
        })
    }
}

impl Fuzzer for ClickHouseFuzzer {
    type Input = Vec<u8>;
    const START_ADDRESS: u64 = SQL_PARSER_ENTRY;
    const MAX_INPUT_LENGTH: usize = 4096; // мб в конфиг перенести какой-то

    fn set_input(&mut self, input: &Self::Input, fuzzvm: &mut FuzzVm<Self>) -> Result<()> {
        fuzzvm.write_bytes_dirty(VirtAddr(0x402004), CR3, input)?; //
        Ok(())
    }

    fn breakpoints(&self) -> Option<&[Breakpoint<Self>]> {
        Some(&[
            Breakpoint {
                lookup: BreakpointLookup::Address(VirtAddr(SQL_PARSER_ENTRY), CR3),
                bp_type: BreakpointType::Repeated,
                bp_hook: |fuzzvm, _input, fuzzer| {
                    fuzzer.handle_sql_parsing(fuzzvm)
                },
            },
        ])
    }
}

impl ClickHouseFuzzer {
    fn execute_input(&mut self, vm: &mut FuzzVm<Self>, input: &[u8]) -> ExecutionResult {
        self.execution_count += 1;

        if input.len() > Self::MAX_INPUT_LENGTH {
            return ExecutionResult::Ok;
        }

        let timeout = std::time::Duration::from_secs(10);
        
        match vm.run_with_timeout(timeout, |vm| {
            self.set_input(input, vm)?;
            
            loop {
                match vm.run_until_breakpoint()? {
                    Execution::Break(bp_idx) => {
                        let current_address = vm.rip().as_u64();
                        self.coverage.insert(current_address);

                        if vm.memory_usage()? > MAX_MEMORY_LIMIT {
                            return Ok(Execution::End);
                        }

                        if let Some(breakpoints) = self.breakpoints() {
                            if let Some(bp) = breakpoints.get(bp_idx) {
                                let result = (bp.bp_hook)(vm, input, self)?;
                                if result != Execution::Continue {
                                    return Ok(result);
                                }
                            }
                        }
                    }
                    Execution::End => break,
                    Execution::Continue => continue,
                }
            }
            Ok(Execution::End)
        }) {
            Ok(_) => ExecutionResult::Ok,
            Err(e) => {
                if e.to_string().contains("SIGSEGV") {
                    let crash_info = self.extract_crash_info(vm, input)?;
                    ExecutionResult::Crash(crash_info)
                } else if e.to_string().contains("timeout") {
                    ExecutionResult::Timeout
                } else {
                    ExecutionResult::Ok
                }
            }
        }
    }

    fn handle_sql_parsing(&mut self, fuzzvm: &mut FuzzVm<Self>) -> Result<Execution> {
        let current_address = fuzzvm.rip().as_u64();
        self.coverage.insert(current_address);

        let parser_state = self.get_parser_state(fuzzvm)?;
        
        match parser_state {
            ParserState::Starting => {
                if !self.check_initial_state(fuzzvm)? {
                    return Ok(Execution::End);
                }
            }
            ParserState::Parsing => {
                if fuzzvm.memory_usage()? > MAX_MEMORY_LIMIT {
                    return Ok(Execution::End);
                }
            }
            ParserState::Error => {
                return Ok(Execution::Break(0));
            }
            ParserState::Completed => {
                return Ok(Execution::End);
            }
        }

        Ok(Execution::Continue)
    }

    fn extract_crash_info(&self, vm: &FuzzVm<Self>, input: &[u8]) -> Result<String> {
        let mut info = String::new();

        info.push_str(&format!("Crash at RIP: {:x}\n", vm.rip().as_u64()));
        info.push_str(&format!("Input: {}\n", String::from_utf8_lossy(input)));

        if let Ok(stack_trace) = vm.get_stack_trace() {
            info.push_str("Stack trace:\n");
            for addr in stack_trace {
                info.push_str(&format!("  {:#x}\n", addr));
            }
        }

        Ok(info)
    }

    fn handle_crash<P: AsRef<Path>>(
        &mut self,
        output_dir: P,
        input: &[u8],
        crash_info: &str,
    ) -> Result<()> {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let mut hasher = DefaultHasher::new();
        crash_info.hash(&mut hasher);
        let crash_hash = format!("{:016x}", hasher.finish());

        if self.crashes.insert(crash_hash.clone()) {
            let crash_dir = output_dir.as_ref().join("crashes");
            std::fs::create_dir_all(&crash_dir)?;

            let input_path = crash_dir.join(format!("crash_{}.sql", crash_hash));
            std::fs::write(input_path, input)?;

            let info_path = crash_dir.join(format!("crash_{}.txt", crash_hash));
            std::fs::write(info_path, crash_info)?;
        }

        Ok(())
    }

    fn get_parser_state(&self, fuzzvm: &mut FuzzVm<Self>) -> Result<ParserState> {
        match fuzzvm.rax() {
            0 => Ok(ParserState::Starting),
            1 => Ok(ParserState::Parsing),
            2 => Ok(ParserState::Completed),
            _ => Ok(ParserState::Error),
        }
    }

    fn check_initial_state(&self, fuzzvm: &mut FuzzVm<Self>) -> Result<bool> {
        Ok(fuzzvm.rsp() != 0 && fuzzvm.rbp() != 0)
    }
}
