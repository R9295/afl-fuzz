use crate::{
    afl_stats::AflStatsStage, feedback::CustomFilepathToTestcaseFeedback, run_fuzzer_with_stage,
    utils::PowerScheduleCustom, Opt, AFL_DEFAULT_INPUT_LEN_MAX, AFL_DEFAULT_INPUT_LEN_MIN,
};
use core::time::Duration;
use libafl_bolts::{
    current_nanos, current_time,
    fs::get_unique_std_input_file,
    ownedref::OwnedRefMut,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, UnixShMemProvider},
    tuples::{tuple_list, Handled, Merge},
    AsSliceMut,
};
use libafl_targets::{cmps::AFLppCmpLogMap, AFLppCmpLogObserver, AFLppCmplogTracingStage};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, collections::HashMap, path::PathBuf};

use crate::corpus::{set_corpus_filepath, set_solution_filepath};
use crate::feedback::{FeedbackLocation, SeedFeedback};
use libafl::{
    corpus::{Corpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::forkserver::{ForkserverExecutor, ForkserverExecutorBuilder},
    feedback_and, feedback_and_fast, feedback_or, feedback_or_fast,
    feedbacks::{ConstFeedback, CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{
        scheduled::havoc_mutations, tokens_mutations, AFLppRedQueen, StdScheduledMutator, Tokens,
    },
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, StdWeightedScheduler},
    stages::{
        mutational::MultiMutationalStage, CalibrationStage, ColorizationStage, IfStage,
        StdPowerMutationalStage,
    },
    state::{HasCorpus, HasCurrentTestcase, HasSolutions, HasStartTime, StdState},
    Error, HasFeedback, HasMetadata, HasObjective,
};

#[allow(clippy::too_many_lines)]
pub fn fuzz<'a>(
    name: String,
    dir: &PathBuf,
    opt: &Opt,
    map_size: usize,
    timeout: Duration,
    target_env: &HashMap<&'a str, &'a str>,
) {
    // Create the shared memory map
    let mut shmem_provider = UnixShMemProvider::new().unwrap();
    let mut shmem = shmem_provider.new_shmem(map_size).unwrap();
    shmem.write_to_env("__AFL_SHM_ID").unwrap();
    let shmem_buf = shmem.as_slice_mut();

    // Create an observation channel to keep track of the edges hit
    let edges_observer = unsafe {
        HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmem_buf)).track_indices()
    };
    let map_feedback = MaxMapFeedback::new(&edges_observer);

    // Create the CalibrationStage; used to measure the stability of an input.
    let calibration = CalibrationStage::new(&map_feedback);

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    // Feedback to decide if the Input is "corpus worthy"
    let mut feedback = SeedFeedback::new(
        feedback_or!(
            feedback_or!(map_feedback, TimeFeedback::new(&time_observer)),
            CustomFilepathToTestcaseFeedback::new(set_corpus_filepath, dir.clone())
        ),
        FeedbackLocation::Feedback,
        opt.clone(),
    );

    // Feedback to decide if the Input is "solution worthy"
    let mut objective = SeedFeedback::new(
        feedback_or!(
            feedback_and_fast!(
                feedback_or_fast!(
                    CrashFeedback::new(),
                    feedback_and!(
                        ConstFeedback::new(!opt.ignore_timeouts),
                        TimeoutFeedback::new()
                    )
                ),
                MaxMapFeedback::with_name("mapfeedback_metadata_objective", &edges_observer)
            ),
            CustomFilepathToTestcaseFeedback::new(set_solution_filepath, dir.clone())
        ),
        FeedbackLocation::Objective,
        opt.clone(),
    );

    // Initialize our State, and it's EventManager utility.
    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        OnDiskCorpus::<BytesInput>::new(dir.join("queue")).unwrap(),
        OnDiskCorpus::<BytesInput>::new(dir).unwrap(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();
    // Create our (sub) directories for Objectives
    std::fs::create_dir(dir.join("crashes")).expect("should be able to create crashes dir");
    std::fs::create_dir(dir.join("hangs")).expect("should be able to create hangs dir");
    let monitor = SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr = SimpleEventManager::new(monitor);

    // Create our Mutational Stage.
    let power = StdPowerMutationalStage::new(StdScheduledMutator::new(
        havoc_mutations().merge(tokens_mutations()),
    ));
    let strategy = opt.power_schedule.unwrap_or(PowerScheduleCustom::Explore);

    // Create our ColorizationStage
    let colorization = ColorizationStage::new(&edges_observer);

    // Create our Scheduler
    let mut weighted_scheduler =
        StdWeightedScheduler::with_schedule(&mut state, &edges_observer, Some(strategy.into()));
    if opt.cycle_schedules {
        weighted_scheduler = weighted_scheduler.cycling_scheduler();
    }
    let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, weighted_scheduler);

    // Create our Fuzzer
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Create the base Executor
    let mut executor = base_executor(opt, timeout, map_size, target_env, &mut shmem_provider);
    // Set a custom exit code to be interpreted as a Crash if configured.
    if let Some(crash_exitcode) = opt.crash_exitcode {
        executor = executor.crash_exitcode(crash_exitcode);
    }

    // Enable autodict if configured
    let mut tokens = Tokens::new();
    if !opt.no_autodict {
        executor = executor.autotokens(&mut tokens);
    };

    // Set a custom directory for the current Input if configured;
    // May be used to provide a ram-disk etc..
    if let Some(cur_input_dir) = &opt.cur_input_dir {
        executor = executor.arg_input_file(cur_input_dir.join(get_unique_std_input_file()));
    }

    // Finalize and build our Executor
    let mut executor = executor
        .build(tuple_list!(time_observer, edges_observer))
        .unwrap();

    // Load our seeds
    // TODO handle auto resume
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
                    &[opt.input_dir.clone()],
                    err
                )
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    // We set IsInitialCorpusEntry as metadata for all initial testcases.
    // Used in Cmplog stage.
    // TODO: use for AFL_NO_STARTUP_CALIBRATION
    for id in state.corpus().ids() {
        let testcase = state.corpus().get(id).expect("should be present in Corpus");
        testcase
            .borrow_mut()
            .add_metadata(IsInitialCorpusEntryMetadata {});
    }

    // Add the tokens to State
    state.add_metadata(tokens);

    // Set the start time of our Fuzzer
    *state.start_time_mut() = current_time();

    // Tell [`SeedFeedback`] that we're done loading seeds; rendering it benign.
    fuzzer.objective_mut().done_loading_seeds();
    fuzzer.feedback_mut().done_loading_seeds();

    // Create a AFLStatsStage TODO: dont hardcore name, derive from  edges observer
    let afl_stats_stage = AflStatsStage::new(
        dir.clone(),
        Duration::from_secs(15),
        timeout
            .as_millis()
            .try_into()
            .expect("do you really need a u128 timeout??"),
        Cow::Borrowed("shared_mem"),  // TODO
        Cow::Borrowed("afl_banner"),  // TODO
        Cow::Borrowed("afl_version"), // TODO
        Cow::Borrowed("target_mode"), // TODO
        "command line".to_string(),   // TODO
    );

    // Set LD_PRELOAD (Linux) && DYLD_INSERT_LIBRARIES (OSX) for target.
    if let Some(preload_env) = &opt.afl_preload {
        std::env::set_var("LD_PRELOAD", preload_env);
        std::env::set_var("DYLD_INSERT_LIBRARIES", preload_env);
    }

    // Create a CmpLog executor if configured.
    if let Some(ref cmplog_binary) = opt.cmplog_binary {
        // The CmpLog map shared between the CmpLog observer and CmpLog executor
        let mut cmplog_shmem = shmem_provider.uninit_on_shmem::<AFLppCmpLogMap>().unwrap();

        // Let the Forkserver know the CmpLog shared memory map ID.
        cmplog_shmem.write_to_env("__AFL_CMPLOG_SHM_ID").unwrap();
        let cmpmap = unsafe { OwnedRefMut::from_shmem(&mut cmplog_shmem) };

        // Create the CmpLog observer.
        let cmplog_observer = AFLppCmpLogObserver::new("cmplog", cmpmap, true);
        let cmplog_ref = cmplog_observer.handle();

        // Create the CmpLog executor.
        // Cmplog has 25% execution overhead so we give it double the timeout
        let cmplog_executor =
            base_executor(opt, timeout * 2, map_size, target_env, &mut shmem_provider)
                .program(cmplog_binary)
                .build(tuple_list!(cmplog_observer))
                .unwrap();

        // Create the CmpLog tracing stage.
        let tracing = AFLppCmplogTracingStage::with_cmplog_observer(cmplog_executor, cmplog_ref);

        // Create a randomic Input2State stage
        let rq = MultiMutationalStage::new(AFLppRedQueen::with_cmplog_options(true, true));

        // Create an IfStage and wrap the CmpLog stages in it.
        // We run cmplog on the second fuzz run of the testcase.
        // This stage checks if the testcase has been fuzzed more than twice, if so do not run cmplog.
        // We also check if it is an initial corpus testcase
        // and if run with AFL_CMPLOG_ONLY_NEW, then we avoid cmplog.
        let cb = |_fuzzer: &mut _,
                  _executor: &mut _,
                  state: &mut StdState<_, OnDiskCorpus<_>, _, _>,
                  _event_manager: &mut _|
         -> Result<bool, Error> {
            let testcase = state.current_testcase()?;
            if opt.cmplog_only_new && testcase.has_metadata::<IsInitialCorpusEntryMetadata>() {
                return Ok(false);
            }
            Ok(testcase.scheduled_count() == 1)
        };
        let cmplog = IfStage::new(cb, tuple_list!(colorization, tracing, rq));

        // The order of the stages matter!
        let mut stages = tuple_list!(calibration, cmplog, power, afl_stats_stage);

        // Run our fuzzer; WITH CmpLog
        run_fuzzer_with_stage!(
            &opt,
            fuzzer,
            &mut stages,
            &mut executor,
            &mut state,
            &mut mgr
        );
    } else {
        // The order of the stages matter!
        let mut stages = tuple_list!(calibration, power, afl_stats_stage);

        // Run our fuzzer; NO CmpLog
        run_fuzzer_with_stage!(
            &opt,
            fuzzer,
            &mut stages,
            &mut executor,
            &mut state,
            &mut mgr
        );
    }
    // TODO: serialize state when exiting.
}

fn base_executor<'a>(
    opt: &'a Opt,
    timeout: Duration,
    map_size: usize,
    target_env: &HashMap<&'a str, &'a str>,
    shmem_provider: &'a mut UnixShMemProvider,
) -> ForkserverExecutorBuilder<'a, UnixShMemProvider> {
    let mut executor = ForkserverExecutor::builder()
        .program(opt.executable.clone())
        .shmem_provider(shmem_provider)
        .coverage_map_size(map_size)
        .is_persistent(opt.is_persistent)
        .kill_signal(opt.kill_signal)
        .debug_child(opt.debug_child)
        .min_input_size(opt.min_input_len.unwrap_or(AFL_DEFAULT_INPUT_LEN_MIN))
        .max_input_size(opt.max_input_len.unwrap_or(AFL_DEFAULT_INPUT_LEN_MAX))
        .envs(target_env)
        .timeout(timeout);
    if let Some(harness_input_type) = &opt.harness_input_stdin {
        executor = executor.parse_afl_cmdline([harness_input_type]);
    }
    executor
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IsInitialCorpusEntryMetadata {}
libafl_bolts::impl_serdeany!(IsInitialCorpusEntryMetadata);
