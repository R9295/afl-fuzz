#![deny(clippy::pedantic)]
use core::time::Duration;
use std::{collections::HashMap, path::PathBuf};
mod afl_stats;
mod feedback;
use clap::Parser;

use fuzzer::fuzz;

mod corpus;
mod fuzzer;
mod utils;
use nix::sys::signal::Signal;
use utils::PowerScheduleCustom;

#[allow(clippy::too_many_lines)]
fn main() {
    let opt = Opt::parse();
    let map_size: usize = opt
        .map_size
        .try_into()
        .expect("we should be able to convert map_size to usize");
    let timeout = Duration::from_millis(opt.hang_timeout);
    let mut target_env = HashMap::new();
    if let Some(ref target_env_str) = opt.target_env {
        let env_regex = regex::Regex::new(r"([^\s=]+)\s*=\s*([^\s]+)").unwrap();
        for vars in env_regex.captures_iter(target_env_str) {
            target_env.insert(
                vars.get(1).expect("should have name").as_str(),
                vars.get(2).expect("should have value").as_str(),
            );
        }
    }
    fuzz(&opt, map_size, timeout, &target_env);
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Parser, Clone)]
#[command(
    name = "afl-fuzz",
    about = "afl-fuzz, now in rust!",
    author = "r9295 <aarnavbos@gmail.com>"
)]
/// The commandline args the fuzzer accepts
struct Opt {
    executable: PathBuf,
    #[arg(value_parser = validate_harness_input_type)]
    harness_input_stdin: Option<String>,

    // NOTE: afl-fuzz does not accept multiple input directories
    #[arg(short = 'i')]
    input_dir: PathBuf,
    #[arg(short = 'o')]
    output_dir: PathBuf,
    #[arg(short = 'p')]
    power_schedule: Option<PowerScheduleCustom>,
    #[arg(short = 'c')]
    cmplog_binary: Option<PathBuf>,
    // Environment + CLI variables
    #[arg(env = "AFL_INPUT_LEN_MAX", short = 'G')]
    max_input_len: Option<usize>,
    #[arg(env = "AFL_INPUT_LEN_MIN", short = 'g')]
    min_input_len: Option<usize>,
    // Environment Variables
    #[arg(env = "AFL_BENCH_JUST_ONE")]
    bench_just_one: bool,
    #[arg(env = "AFL_BENCH_UNTIL_CRASH")]
    bench_until_crash: bool,
    #[arg(env = "AFL_HANG_TMOUT", default_value_t = 100)]
    hang_timeout: u64,
    #[arg(env = "AFL_DEBUG_CHILD")]
    debug_child: bool,
    #[arg(env = "AFL_PERSISTENT")]
    is_persistent: bool,
    #[arg(env = "AFL_NO_AUTODICT")]
    no_autodict: bool,
    #[arg(env = "AFL_KILL_SIGNAL", default_value_t = Signal::SIGKILL)]
    kill_signal: Signal,
    #[arg(env = "AFL_MAP_SIZE", default_value_t = 65536,
        value_parser= validate_map_size)]
    map_size: u32,
    #[arg(env = "AFL_IGNORE_TIMEOUTS")]
    ignore_timeouts: bool,
    #[arg(env = "AFL_TMPDIR")]
    cur_input_dir: Option<PathBuf>,
    #[arg(env = "AFL_CRASH_EXITCODE")]
    crash_exitcode: Option<i8>,
    #[arg(env = "AFL_TARGET_ENV")]
    target_env: Option<String>,
    #[arg(env = "AFL_CYCLE_SCHEDULES")]
    cycle_schedules: bool,
    #[arg(env = "AFL_CMPLOG_ONLY_NEW")]
    cmplog_only_new: bool,

    // Seed config
    #[arg(env = "AFL_EXIT_ON_SEED_ISSUES")]
    exit_on_seed_issues: bool,
    // renamed from IGNORE_SEED_PROBLEMS
    #[arg(env = "AFL_IGNORE_SEED_ISSUES")]
    ignore_seed_issues: bool,
    #[arg(env = "AFL_CRASHING_SEED_AS_NEW_CRASH")]
    crash_seed_as_new_crash: bool,
}

const AFL_MAP_SIZE_MIN: u32 = u32::pow(2, 3);
const AFL_MAP_SIZE_MAX: u32 = u32::pow(2, 30);

const AFL_DEFAULT_INPUT_LEN_MAX: usize = 1_048_576;
const AFL_DEFAULT_INPUT_LEN_MIN: usize = 1;

fn validate_map_size(s: &str) -> Result<u32, String> {
    let map_size: u32 = s
        .parse()
        .map_err(|_| format!("`{s}` isn't a valid unsigned integer"))?;
    if map_size > AFL_MAP_SIZE_MIN && map_size < AFL_MAP_SIZE_MAX {
        Ok(map_size)
    } else {
        Err(format!(
            "AFL_MAP_SIZE not in range {AFL_MAP_SIZE_MIN} (2 ^ 3) - {AFL_MAP_SIZE_MAX} (2 ^ 30)",
        ))
    }
}

fn validate_harness_input_type(s: &str) -> Result<String, String> {
    if s != "@@" {
        return Err("Unknown harness input type. Use \"@@\" for file, omit for stdin ".to_string());
    }
    Ok(s.to_string())
}
