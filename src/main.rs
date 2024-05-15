/// Using `https://github.com/AFLplusplus/LibAFL/tree/main/fuzzers/forkserver_simple`
use core::time::Duration;
use std::{collections::HashMap, path::PathBuf};
mod feedback;
use clap::Parser;
use feedback::{FeedbackLocation, SeedFeedback};
use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::forkserver::ForkserverExecutor,
    feedback_and, feedback_and_fast, feedback_or, feedback_or_fast,
    feedbacks::{ConstFeedback, CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{scheduled::havoc_mutations, tokens_mutations, StdScheduledMutator, Tokens},
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, StdWeightedScheduler,
    },
    stages::{mutational::StdMutationalStage, CalibrationStage},
    state::{HasCorpus, HasSolutions, StdState},
    HasFeedback, HasMetadata, HasObjective,
};
use libafl_bolts::{
    current_nanos,
    fs::get_unique_std_input_file,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, UnixShMemProvider},
    tuples::{tuple_list, Merge},
    AsSliceMut,
};
use nix::sys::signal::Signal;

const AFL_MAP_SIZE_MIN: u32 = u32::pow(2, 3);
const AFL_MAP_SIZE_MAX: u32 = u32::pow(2, 30);

fn main() {
    let opt = Opt::parse();
    let map_size: usize = opt
        .map_size
        .try_into()
        .expect("we should be able to convert map_size to usize");

    let mut shmem_provider = UnixShMemProvider::new().unwrap();
    let mut shmem = shmem_provider.new_shmem(map_size).unwrap();
    shmem.write_to_env("__AFL_SHM_ID").unwrap();
    let shmem_buf = shmem.as_slice_mut();

    // Create an observation channel using the signals map
    let edges_observer = unsafe {
        HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmem_buf)).track_indices()
    };

    let map_feedback = MaxMapFeedback::new(&edges_observer);

    let calibration = CalibrationStage::new(&map_feedback);
    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = SeedFeedback::new(
        feedback_or!(map_feedback, TimeFeedback::new(&time_observer)),
        FeedbackLocation::Feedback,
        opt.clone(),
    );
    let mut objective = SeedFeedback::new(
        feedback_and_fast!(
            feedback_or_fast!(
                CrashFeedback::new(),
                // TODO: benchmark, potentially implement `ConditionalFeedback`.
                // This is a hack to ensure the types of objectitve remain the same in case of
                // ignore_timeouts
                feedback_and!(
                    ConstFeedback::new(!opt.ignore_timeouts),
                    TimeoutFeedback::new()
                )
            ),
            MaxMapFeedback::with_name("mapfeedback_metadata_objective", &edges_observer)
        ),
        feedback::FeedbackLocation::Objective,
        opt.clone(),
    );
    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::<BytesInput>::new(),
        OnDiskCorpus::new(opt.output_dir).unwrap(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();
    let monitor = SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr = SimpleEventManager::new(monitor);
    let strategy = opt.power_schedule.unwrap_or(PowerScheduleCustom::EXPLORE);
    let scheduler = IndexesLenTimeMinimizerScheduler::new(
        &edges_observer,
        StdWeightedScheduler::with_schedule(&mut state, &edges_observer, Some(strategy.into())),
    );
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
    let mut tokens = Tokens::new();
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
    let mut executor = ForkserverExecutor::builder()
        .program(opt.executable)
        .shmem_provider(&mut shmem_provider)
        .coverage_map_size(map_size)
        .is_persistent(opt.is_persistent)
        .kill_signal(opt.kill_signal)
        .debug_child(opt.debug_child)
        .envs(target_env)
        .timeout(Duration::from_millis(opt.hang_timeout));
    if let Some(crash_exitcode) = opt.crash_exitcode {
        executor = executor.crash_exitcode(crash_exitcode)
    }
    if !opt.no_autodict {
        executor = executor.autotokens(&mut tokens);
    };
    if let Some(cur_input_dir) = opt.cur_input_dir {
        executor = executor.arg_input_file(cur_input_dir.join(get_unique_std_input_file()))
    }
    let mut executor = executor
        .build(tuple_list!(time_observer, edges_observer))
        .unwrap();
    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(
                &mut fuzzer,
                &mut executor,
                &mut mgr,
                &[opt.input_dir.clone()],
            )
            .unwrap_or_else(|err| {
                panic!(
                    "Failed to load initial corpus at {:?}: {:?}",
                    &[opt.input_dir],
                    err
                )
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }
    state.add_metadata(tokens);

    fuzzer.objective_mut().done_loading_seeds();
    fuzzer.feedback_mut().done_loading_seeds();

    let mutator =
        StdScheduledMutator::with_max_stack_pow(havoc_mutations().merge(tokens_mutations()), 6);
    let mut stages = tuple_list!(calibration, StdMutationalStage::new(mutator),);
    if opt.bench_just_one {
        fuzzer
            .fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut mgr, 1)
            .expect("Error benching just once");
    } else if opt.bench_until_crash {
        loop {
            fuzzer
                .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
                .expect("error fuzzing one;");
            if state.solutions().count() > 0 {
                break;
            }
        }
    } else {
        fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("Error in the fuzzing loop");
    }
    // TODO: serialize state when exiting.
}

/// The power schedule to use; Copied so we can use clap::ValueEnum
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerScheduleCustom {
    /// The `explore` power schedule
    EXPLORE,
    /// The `exploit` power schedule
    EXPLOIT,
    /// The `fast` power schedule
    FAST,
    /// The `coe` power schedule
    COE,
    /// The `lin` power schedule
    LIN,
    /// The `quad` power schedule
    QUAD,
}

impl From<PowerScheduleCustom> for PowerSchedule {
    fn from(val: PowerScheduleCustom) -> Self {
        match val {
            PowerScheduleCustom::EXPLORE => PowerSchedule::EXPLORE,
            PowerScheduleCustom::COE => PowerSchedule::COE,
            PowerScheduleCustom::LIN => PowerSchedule::LIN,
            PowerScheduleCustom::FAST => PowerSchedule::FAST,
            PowerScheduleCustom::QUAD => PowerSchedule::QUAD,
            PowerScheduleCustom::EXPLOIT => PowerSchedule::EXPLOIT,
        }
    }
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

    // NOTE: afl-fuzz does not accept multiple input directories
    #[arg(short = 'i')]
    input_dir: PathBuf,
    #[arg(short = 'o')]
    output_dir: PathBuf,
    #[arg(short = 'p')]
    power_schedule: Option<PowerScheduleCustom>,
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

    // Seed config
    #[arg(env = "AFL_EXIT_ON_SEED_ISSUES")]
    exit_on_seed_issues: bool,
    // renamed from IGNORE_SEED_PROBLEMS
    #[arg(env = "AFL_IGNORE_SEED_ISSUES")]
    ignore_seed_issues: bool,
    #[arg(env = "AFL_CRASHING_SEED_AS_NEW_CRASH")]
    crash_seed_as_new_crash: bool,
}

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
