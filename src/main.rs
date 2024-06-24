#![deny(clippy::pedantic)]
use core::time::Duration;
use std::{collections::HashMap, net::SocketAddr, path::PathBuf};
mod afl_stats;
mod feedback;
use clap::Parser;

use corpus::{check_autoresume, main_node_exists};
mod corpus;
mod executor;
mod fuzzer;
mod hooks;
mod utils;
use fuzzer::{run_client, LibaflFuzzState};
use hooks::LibAflFuzzEventHook;
use libafl::{
    events::{EventConfig, Launcher},
    monitors::MultiMonitor,
    Error,
};
use libafl_bolts::{
    core_affinity::Cores,
    shmem::{ShMemProvider, UnixShMemProvider},
    tuples::tuple_list,
};
use nix::sys::signal::Signal;
use utils::PowerScheduleCustom;

#[allow(clippy::too_many_lines)]
fn main() {
    let mut opt = Opt::parse();
    let map_size: usize = opt
        .map_size
        .try_into()
        .expect("we should be able to convert map_size to usize");
    let timeout = Duration::from_millis(opt.hang_timeout);

    executor::check_binary(&mut opt, SHMEM_ENV_VAR).expect("binary to be valid");

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

    // Create the shared memory map provider for LLMP
    let shmem_provider = UnixShMemProvider::new().unwrap();

    // Create our Monitor
    let monitor = MultiMonitor::new(|s| println!("{s}"));
    /*     let monitor = MultiMonitor::new(|s| {}); */

    opt.auto_resume = match opt.auto_resume {
        false => opt.input_dir.as_os_str() == "-",
        true => true,
    };
    // TODO: check if we need to auto-resume.
    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::AlwaysUnique)
        .monitor(monitor)
        .run_client(|state: Option<_>, restarting_mgr: _, core_id: _| {
            run_client(
                state,
                restarting_mgr,
                core_id,
                &opt,
                map_size,
                timeout,
                &target_env,
            )
        })
        .cores(&opt.cores)
        .broker_port(opt.broker_port)
        .remote_broker_addr(opt.broker_addr)
        .stdout_file(Some("/dev/null"))
        .build()
        .launch_with_hooks(tuple_list!(LibAflFuzzEventHook::new(opt.bench_until_crash)))
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }
    // TODO: run this on cleanup / register ctrl-c handler
    /* if is_main_node {
        std::fs::remove_file(fuzzer_dir.join("is_main_node"))
            .expect("main node should have is_main_node file");
    } */
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Parser, Clone)]
#[command(
    name = "afl-fuzz",
    about = "afl-fuzz, now in rust!",
    author = "r9295 <aarnavbos@gmail.com>"
)]
/// The Configuration
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
    #[arg(short = 'F')]
    foreign_sync_dirs: Vec<PathBuf>,
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
    #[arg(env = "AFL_PRELOAD")]
    afl_preload: Option<String>,
    #[arg(env = "AFL_AUTORESUME")]
    auto_resume: bool,
    #[arg(env = "AFL_SKIP_BIN_CHECK")]
    skip_bin_check: bool,
    #[arg(env = "AFL_DEFER_FORKSRV")]
    defer_forkserver: bool,
    /// in seconds
    #[arg(env = "AFL_FUZZER_STATS_UPDATE_INTERVAL", default_value = "60")]
    stats_interval: u64,

    // New Environment Variables
    #[arg(env = "AFL_NUM_CORES", value_parser = Cores::from_cmdline)]
    cores: Cores,
    #[arg(env = "AFL_BROKER_PORT", default_value = "1337")]
    broker_port: u16,
    #[arg(env = "AFL_BROKER_ADDR")]
    broker_addr: Option<SocketAddr>,

    // Seed config
    #[arg(env = "AFL_EXIT_ON_SEED_ISSUES")]
    exit_on_seed_issues: bool,
    // renamed from IGNORE_SEED_PROBLEMS
    #[arg(env = "AFL_IGNORE_SEED_ISSUES")]
    ignore_seed_issues: bool,
    #[arg(env = "AFL_CRASHING_SEED_AS_NEW_CRASH")]
    crash_seed_as_new_crash: bool,

    uses_asan: bool,
    frida_mode: bool,
    qemu_mode: bool,
    nyx_mode: bool,
}

const AFL_MAP_SIZE_MIN: u32 = u32::pow(2, 3);
const AFL_MAP_SIZE_MAX: u32 = u32::pow(2, 30);

const AFL_DEFAULT_INPUT_LEN_MAX: usize = 1_048_576;
const AFL_DEFAULT_INPUT_LEN_MIN: usize = 1;
const OUTPUT_GRACE: u64 = 25;

const PERSIST_SIG: &str = "##SIG_AFL_PERSISTENT##";
const DEFER_SIG: &str = "##SIG_AFL_DEFER_FORKSRV##";
const SHMEM_ENV_VAR: &str = "__AFL_SHM_ID";
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
