/// Using `https://github.com/AFLplusplus/LibAFL/tree/main/fuzzers/forkserver_simple`
use core::time::Duration;
use std::path::PathBuf;

use clap::Parser;
use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::forkserver::ForkserverExecutor,
    feedback_and_fast, feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{scheduled::havoc_mutations, tokens_mutations, StdScheduledMutator, Tokens},
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, StdState},
    HasMetadata,
};
use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, UnixShMemProvider},
    tuples::{tuple_list, Merge},
    AsMutSlice,
};
#[allow(clippy::similar_names)]
pub fn main() {
    const MAP_SIZE: usize = 65536;
    let opt = Opt::parse();
    let mut shmem_provider = UnixShMemProvider::new().unwrap();
    let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    shmem.write_to_env("__AFL_SHM_ID").unwrap();
    let shmem_buf = shmem.as_mut_slice();
    let edges_observer = unsafe {
        HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmem_buf)).track_indices()
    };
    let time_observer = TimeObserver::new("time");
    let mut feedback = feedback_or!(
        MaxMapFeedback::new(&edges_observer),
        TimeFeedback::with_observer(&time_observer)
    );
    let mut objective = feedback_and_fast!(
        CrashFeedback::new(),
        MaxMapFeedback::with_name("mapfeedback_metadata_objective", &edges_observer)
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
    let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
    let mut tokens = Tokens::new();
    let mut executor = ForkserverExecutor::builder()
        .program(opt.executable)
        .shmem_provider(&mut shmem_provider)
        .autotokens(&mut tokens)
        .coverage_map_size(MAP_SIZE)
        .timeout(Duration::from_millis(1000))
        .build(tuple_list!(time_observer, edges_observer))
        .unwrap();
    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[opt.input_dir.clone()])
            .unwrap_or_else(|err| {
                panic!(
                    "Failed to load initial corpus at {:?}: {:?}",
                    &[opt.input_dir], err
                )
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }
    state.add_metadata(tokens);
    let mutator =
        StdScheduledMutator::with_max_stack_pow(havoc_mutations().merge(tokens_mutations()), 6);
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));
    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}

/// The commandline args this fuzzer accepts
#[derive(Debug, Parser)]
#[command(
    name = "afl-fuzz",
    about = "afl-fuzz, now in rust!",
    author = "r9295 <aarnavbos@gmail.com>"
)]
struct Opt {
    executable: PathBuf,
    // NOTE: afl-fuzz does not accept multiple input directories
    #[arg(short = 'i')]
    input_dir: PathBuf,
    #[arg(short = 'o')]
    output_dir: PathBuf,
}
