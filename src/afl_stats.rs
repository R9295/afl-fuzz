/// Stage for stats generation
#[allow(clippy::module_name_repetitions)]
use core::{marker::PhantomData, time::Duration};
use std::{
    borrow::Cow,
    fmt::Display,
    fs::OpenOptions,
    io::{self, Write},
    mem,
    path::PathBuf,
    process, u128, usize,
};

use libafl_bolts::current_time;
use nix::libc::{getrusage, rusage, RUSAGE_CHILDREN};

use libafl::{
    corpus::{Corpus, HasCurrentCorpusId, SchedulerTestcaseMetadata, Testcase},
    events::{Event, EventFirer},
    inputs::UsesInput,
    schedulers::{minimizer::IsFavoredMetadata, SchedulerMetadata},
    stages::{calibrate::UnstableEntriesMetadata, Stage},
    state::{HasCorpus, HasExecutions, HasImported, HasStartTime, UsesState},
    Error, HasMetadata, HasNamedMetadata,
};

#[allow(clippy::module_name_repetitions)]
/// The [`AflStatsStage`] is a simple stage that computes and reports some stats.
#[derive(Debug, Clone)]
pub struct AflStatsStage<E, EM, Z>
where
    E: UsesState,
    EM: EventFirer<State = E::State>,
    Z: UsesState<State = E::State>,
{
    corpus_dir: PathBuf,
    start_time: u64,
    /// name of the map observer
    map_name: Cow<'static, str>,
    // the number of testcases that have been fuzzed
    has_fuzzed_size: usize,
    // the number of "favored" testcases
    is_favored_size: usize,
    // the last time that we report all stats
    last_report_time: Duration,
    // the interval at which we report all stats
    stats_report_interval: Duration,
    pid: u32,
    slowest_exec: Duration,
    max_depth: u64,
    cycles_done: u64,
    saved_crashes: u64,
    saved_hangs: u64,
    last_find: Duration,
    last_hang: Duration,
    last_crash: Duration,
    exec_timeout: u64,
    execs_at_last_objective: u64,
    cycles_wo_finds: u64,
    /// banner text (e.g., the target name)
    afl_banner: Cow<'static, str>,
    /// the version of AFL++ used
    afl_version: Cow<'static, str>,
    /// default, persistent, qemu, unicorn, non-instrumented
    target_mode: Cow<'static, str>,
    /// full command line used for the fuzzing session
    command_line: String,
    phantom: PhantomData<(E, EM, Z)>,
}

#[derive(Debug, Clone)]
pub struct AFLFuzzerStats<'a> {
    /// unix time indicating the start time of afl-fuzz
    start_time: u64,
    /// unix time corresponding to the last interval
    last_update: u64,
    /// run time in seconds to the last update of this file
    run_time: u64,
    /// process id of the fuzzer process
    fuzzer_pid: u32,
    /// queue cycles completed so far
    cycles_done: u64,
    /// number of queue cycles without any new paths found
    cycles_wo_find: u64,
    /// longest time in seconds no new path was found
    time_wo_finds: u64,
    /// TODO
    fuzz_time: u64,
    /// TODO
    calibration_time: u64,
    /// TODO
    sync_time: u64,
    /// TODO
    trim_time: u64,
    /// number of fuzzer executions attempted (what does attempted mean here?)
    execs_done: u64,
    /// overall number of execs per second
    execs_per_sec: u64,
    /// TODO
    execs_ps_last_min: u64,
    /// total number of entries in the queue
    corpus_count: usize,
    /// number of queue entries that are favored
    corpus_favored: usize,
    /// number of entries discovered through local fuzzing
    corpus_found: usize,
    /// number of entries imported from other instances
    corpus_imported: usize,
    /// number of levels in the generated data set
    max_depth: u64,
    /// currently processed entry number
    cur_item: usize,
    /// number of favored entries still waiting to be fuzzed
    pending_favs: usize,
    /// number of all entries waiting to be fuzzed
    pending_total: usize,
    /// number of test cases showing variable behavior
    corpus_variable: u64,
    /// percentage of bitmap bytes that behave consistently
    stability: f64,
    /// percentage of edge coverage found in the map so far,
    bitmap_cvg: f64,
    /// number of unique crashes recorded
    saved_crashes: u64,
    /// number of unique hangs encountered
    saved_hangs: u64,
    /// seconds since the last find was found
    last_find: Duration,
    /// seconds since the last crash was found
    last_crash: Duration,
    /// seconds since the last hang was found
    last_hang: Duration,
    /// execs since the last crash was found
    execs_since_crash: u64,
    /// the -t command line value
    exec_timeout: u64,
    /// real time of the slowest execution in ms
    slowest_exec_ms: u128,
    /// max rss usage reached during fuzzing in MB
    peak_rss_mb: i64,
    /// TODO
    cpu_affinity: i64,
    /// how many edges have been found
    edges_found: u64,
    /// TODO:
    total_edges: u64,
    /// how many edges are non-deterministic
    var_byte_count: usize,
    /// TODO:
    havoc_expansion: usize,
    /// TODO:
    auto_dict_entries: usize,
    /// TODO:
    testcache_size: usize,
    /// TODO:
    testcache_count: usize,
    /// TODO:
    testcache_evict: usize,
    /// banner text (e.g., the target name)
    afl_banner: &'a Cow<'static, str>,
    /// the version of AFL++ used
    afl_version: &'a Cow<'static, str>,
    /// default, persistent, qemu, unicorn, non-instrumented
    target_mode: &'a Cow<'static, str>,
    /// full command line used for the fuzzing session
    command_line: &'a str,
}

#[derive(Debug, Clone)]
pub struct AFLPlotData<'a> {
    relative_time: &'a u64,
    cycles_done: &'a u64,
    cur_item: &'a usize,
    corpus_count: &'a usize,
    pending_total: &'a usize,
    pending_favs: &'a usize,
    /// Note: renamed `map_size` -> `total_edges` for consistency with `fuzzer_stats`
    total_edges: &'a u64,
    saved_crashes: &'a u64,
    saved_hangs: &'a u64,
    max_depth: &'a u64,
    execs_per_sec: &'a u64,
    /// Note: renamed `total_execs` -> `execs_done` for consistency with `fuzzer_stats`
    execs_done: &'a u64,
    edges_found: &'a u64,
}

impl<E, EM, Z> UsesState for AflStatsStage<E, EM, Z>
where
    E: UsesState,
    EM: EventFirer<State = E::State>,
    Z: UsesState<State = E::State>,
{
    type State = E::State;
}

impl<E, EM, Z> Stage<E, EM, Z> for AflStatsStage<E, EM, Z>
where
    E: UsesState,
    EM: EventFirer<State = E::State>,
    Z: UsesState<State = E::State>,
    E::State:
        HasImported + HasCorpus + HasMetadata + HasStartTime + HasExecutions + HasNamedMetadata,
{
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut E::State,
        _manager: &mut EM,
    ) -> Result<(), Error> {
        _manager.fire(state, Event::Stop)?;
        let Some(corpus_idx) = state.current_corpus_id()? else {
            return Err(Error::illegal_state(
                "state is not currently processing a corpus index",
            ));
        };
        let testcase = state.corpus().get(corpus_idx)?.borrow();
        // NOTE: scheduled_count represents the amount of fuzzing iterations a
        // testcase has had. Since this stage is kept at the very end of stage list,
        // the entry would have been fuzzed already (and should contain IsFavoredMetadata) but would have a scheduled count of zero
        // since the scheduled count is incremented after all stages have been run.
        if testcase.scheduled_count() == 0 {
            // New testcase!
            self.cycles_wo_finds = 0;
            self.update_last_find();
            self.maybe_update_last_crash(&testcase, state);
            self.maybe_update_last_hang(&testcase, state);
            self.update_has_fuzzed_size();
            self.maybe_update_is_favored_size(&testcase);
        }
        self.maybe_update_slowest_exec(&testcase);
        self.maybe_update_max_depth(&testcase)?;

        // See if we actually need to run the stage, if not, avoid dynamic value computation.
        if !self.check_interval() {
            return Ok(());
        }

        let corpus_size = state.corpus().count();
        let total_executions = *state.executions();

        let scheduler_metadata = state.metadata::<SchedulerMetadata>().unwrap();
        let queue_cycles = scheduler_metadata.queue_cycles();
        self.maybe_update_cycles(queue_cycles);
        self.maybe_update_cycles_wo_finds(queue_cycles);

        let filled_entries_in_map = scheduler_metadata.bitmap_entries();
        let map_size = scheduler_metadata.bitmap_size();

        let unstable_entries_metadata = state
            .metadata_map()
            .get::<UnstableEntriesMetadata>()
            .unwrap();
        let unstable_entries_in_map = unstable_entries_metadata.unstable_entries().len();

        let stats = AFLFuzzerStats {
            start_time: self.start_time,
            last_update: self.last_report_time.as_secs(),
            run_time: self.last_report_time.as_secs() - self.start_time,
            fuzzer_pid: self.pid,
            cycles_done: queue_cycles,
            cycles_wo_find: self.cycles_wo_finds,
            fuzz_time: 0,        // TODO
            calibration_time: 0, // TODO
            sync_time: 0,        // TODO
            trim_time: 0,        // TODO
            execs_done: total_executions,
            execs_per_sec: *state.executions(),     // TODO
            execs_ps_last_min: *state.executions(), // TODO
            max_depth: self.max_depth,
            corpus_count: corpus_size,
            corpus_favored: corpus_size - self.is_favored_size,
            corpus_found: corpus_size - state.imported(),
            corpus_imported: *state.imported(),
            cur_item: corpus_idx.into(),
            pending_total: corpus_size - self.has_fuzzed_size,
            pending_favs: 0, // TODO
            time_wo_finds: (current_time() - self.last_find).as_secs(),
            corpus_variable: 0,
            stability: self.calculate_stability(unstable_entries_in_map, filled_entries_in_map),
            bitmap_cvg: filled_entries_in_map as f64 / map_size as f64,
            saved_crashes: self.saved_crashes,
            saved_hangs: self.saved_hangs,
            last_find: self.last_find,
            last_hang: self.last_hang,
            last_crash: self.last_crash,
            execs_since_crash: total_executions - self.execs_at_last_objective,
            exec_timeout: self.exec_timeout, // TODO
            slowest_exec_ms: self.slowest_exec.as_millis(),
            peak_rss_mb: self.peak_rss_mb()?,
            cpu_affinity: 0, // TODO
            total_edges: map_size,
            edges_found: filled_entries_in_map,
            var_byte_count: unstable_entries_metadata.unstable_entries().len(),
            havoc_expansion: 0,   // TODO
            auto_dict_entries: 0, // TODO
            testcache_size: 0,
            testcache_count: 0,
            testcache_evict: 0,
            afl_banner: &self.afl_banner,
            afl_version: &self.afl_version,
            target_mode: &self.target_mode,
            command_line: &self.command_line,
        };
        let plot_data = AFLPlotData {
            corpus_count: &stats.corpus_count,
            cur_item: &stats.cur_item,
            cycles_done: &stats.cycles_done,
            edges_found: &stats.edges_found,
            total_edges: &stats.total_edges,
            execs_per_sec: &stats.execs_per_sec,
            pending_total: &stats.pending_total,
            pending_favs: &stats.pending_favs,
            max_depth: &stats.max_depth,
            relative_time: &stats.run_time,
            saved_hangs: &stats.saved_hangs,
            saved_crashes: &stats.saved_crashes,
            execs_done: &stats.execs_done,
        };
        self.write_fuzzer_stats(&stats)?;
        self.write_plot_data(&plot_data)?;
        Ok(())
    }
    fn should_restart(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        Ok(true)
    }
    fn clear_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        Ok(())
    }
}

impl<E, EM, Z> AflStatsStage<E, EM, Z>
where
    E: UsesState,
    EM: EventFirer<State = E::State>,
    Z: UsesState<State = E::State>,
    E::State: HasImported + HasCorpus + HasMetadata + HasExecutions,
{
    /// create a new instance of the [`AflStatsStage`]
    #[must_use]
    pub fn new(
        corpus_dir: PathBuf,
        interval: Duration,
        exec_timeout: u64,
        map_name: Cow<'static, str>,
        afl_banner: Cow<'static, str>,
        afl_version: Cow<'static, str>,
        target_mode: Cow<'static, str>,
        command_line: String,
    ) -> Self {
        if !corpus_dir.join("plot_data").exists() {
            std::fs::write(corpus_dir.join("plot_data"), AFLPlotData::get_header()).unwrap();
        }
        if !corpus_dir.join("fuzzer_stats").exists() {
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(corpus_dir.join("fuzzer_stats"))
                .unwrap();
        }
        Self {
            start_time: current_time().as_secs(),
            map_name,
            stats_report_interval: interval,
            has_fuzzed_size: 0,
            is_favored_size: 0,
            cycles_done: 0,
            cycles_wo_finds: 0,
            execs_at_last_objective: 0,
            last_crash: current_time(),
            last_find: current_time(),
            last_hang: current_time(),
            max_depth: 0,
            saved_hangs: 0,
            saved_crashes: 0,
            slowest_exec: Duration::from_secs(0),
            last_report_time: current_time(),
            pid: process::id(),
            exec_timeout,
            target_mode,
            afl_banner,
            afl_version,
            command_line,
            corpus_dir,
            phantom: PhantomData,
        }
    }

    fn write_fuzzer_stats(&self, stats: &AFLFuzzerStats) -> Result<(), Error> {
        std::fs::write(self.corpus_dir.join("fuzzer_stats"), stats.to_string())?;
        Ok(())
    }

    fn write_plot_data(&self, plot_data: &AFLPlotData) -> Result<(), Error> {
        let mut file = OpenOptions::new()
            .append(true)
            .open(self.corpus_dir.join("plot_data"))?;
        writeln!(file, "{plot_data}")?;
        Ok(())
    }

    // Derived from https://github.com/RustPython/RustPython/blob/7996a10116681e9f85eda03413d5011b805e577f/stdlib/src/resource.rs#L113
    // LICENSE: MIT https://github.com/RustPython/RustPython/commit/37355d612a451fba7fef8f13a1b9fdd51310b37e
    fn peak_rss_mb(&self) -> Result<i64, Error> {
        let rss = unsafe {
            let mut rusage = mem::MaybeUninit::<rusage>::uninit();
            if getrusage(RUSAGE_CHILDREN, rusage.as_mut_ptr()) == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(rusage.assume_init())
            }
        }?;
        Ok(rss.ru_maxrss >> 10)
    }

    fn maybe_update_is_favored_size(
        &mut self,
        testcase: &Testcase<<<E as UsesState>::State as UsesInput>::Input>,
    ) {
        if testcase.has_metadata::<IsFavoredMetadata>() {
            self.is_favored_size += 1;
        }
    }

    fn maybe_update_slowest_exec(
        &mut self,
        testcase: &Testcase<<<E as UsesState>::State as UsesInput>::Input>,
    ) {
        if let Some(exec_time) = testcase.exec_time() {
            if exec_time > &self.slowest_exec {
                self.slowest_exec = *exec_time;
            }
        }
    }

    fn update_has_fuzzed_size(&mut self) {
        self.has_fuzzed_size += 1;
    }

    fn maybe_update_max_depth(
        &mut self,
        testcase: &Testcase<<<E as UsesState>::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        if let Ok(metadata) = testcase.metadata::<SchedulerTestcaseMetadata>() {
            if metadata.depth() > self.max_depth {
                self.max_depth = metadata.depth();
            }
        } else {
            return Err(Error::illegal_state(
                "testcase must have scheduler metdata?",
            ));
        }
        Ok(())
    }

    fn update_last_find(&mut self) {
        self.last_find = current_time();
    }

    fn maybe_update_last_crash(
        &mut self,
        testcase: &Testcase<<<E as UsesState>::State as UsesInput>::Input>,
        state: &E::State,
    ) {
        if testcase
            .hit_objectives()
            .contains(&Cow::Borrowed("CrashFeedback"))
        {
            self.last_crash = current_time();
            self.execs_at_last_objective = *state.executions();
        }
    }

    fn maybe_update_last_hang(
        &mut self,
        testcase: &Testcase<<<E as UsesState>::State as UsesInput>::Input>,
        state: &E::State,
    ) {
        if testcase
            .hit_objectives()
            .contains(&Cow::Borrowed("TimeoutFeedback"))
        {
            self.last_hang = current_time();
            self.execs_at_last_objective = *state.executions();
        }
    }

    fn check_interval(&mut self) -> bool {
        let cur = current_time();
        if cur.checked_sub(self.last_report_time).unwrap_or_default() > self.stats_report_interval {
            self.last_report_time = cur;
            return true;
        }
        false
    }
    fn maybe_update_cycles(&mut self, queue_cycles: u64) {
        if queue_cycles > self.cycles_done {
            self.cycles_done += 1;
        }
    }

    fn maybe_update_cycles_wo_finds(&mut self, queue_cycles: u64) {
        if queue_cycles > self.cycles_done && self.last_find < current_time() {
            self.cycles_wo_finds += 1;
        }
    }

    fn calculate_stability(&self, unstable_entries: usize, filled_entries: u64) -> f64 {
        (filled_entries as f64 - unstable_entries as f64) / filled_entries as f64
    }
}

impl Display for AFLPlotData<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}",
            self.relative_time,
            self.cycles_done,
            self.cur_item,
            self.corpus_count,
            self.pending_total,
            self.pending_favs,
            self.total_edges,
            self.saved_crashes,
            self.saved_hangs,
            self.max_depth,
            self.execs_per_sec,
            self.execs_done,
            self.edges_found
        )
    }
}
impl AFLPlotData<'_> {
    fn get_header() -> String {
        "# relative_time, cycles_done, cur_item, corpus_count, pending_total, pending_favs, total_edges, saved_crashes, saved_hangs, max_depth, execs_per_sec, execs_done, edges_found".to_string()
    }
}

impl Display for AFLFuzzerStats<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "start_time       : {} 
last_update       : {}
run_time          : {} 
fuzzer_pid        : {} 
cycles_done       : {} 
cycles_wo_finds   : {} 
time_wo_finds     : {} 
fuzz_time         : {} 
calibration_time  : {} 
sync_time         : {} 
trim_time         : {} 
execs_done        : {} 
execs_per_sec     : {} 
execs_ps_last_min : {} 
corpus_count      : {} 
corpus_favored    : {} 
corpus_found      : {} 
corpus_imported   : {} 
corpus_variable   : {} 
max_depth         : {} 
cur_item          : {} 
pending_favs      : {} 
pending_total     : {} 
stability         : {}% 
bitmap_cvg        : {}% 
saved_crashes     : {} 
saved_hangs       : {} 
last_find         : {} 
last_crash        : {} 
last_hang         : {} 
execs_since_crash : {} 
exec_timeout      : {} 
slowest_exec_ms   : {} 
peak_rss_mb       : {} 
cpu_affinity      : {} 
edges_found       : {} 
total_edges       : {} 
var_byte_count    : {} 
havoc_expansion   : {} 
auto_dict_entries : {} 
testcache_size    : {} 
testcache_count   : {} 
testcache_evict   : {} 
afl_banner        : {} 
afl_version       : {} 
target_mode       : {} 
command_line      : {} 
",
            self.start_time,
            self.last_update,
            self.run_time,
            self.fuzzer_pid,
            self.cycles_done,
            self.cycles_wo_find,
            self.time_wo_finds,
            self.fuzz_time,
            self.calibration_time,
            self.sync_time,
            self.trim_time,
            self.execs_done,
            self.execs_per_sec,
            self.execs_ps_last_min,
            self.corpus_count,
            self.corpus_favored,
            self.corpus_found,
            self.corpus_imported,
            self.corpus_variable,
            self.max_depth,
            self.cur_item,
            self.pending_favs,
            self.pending_total,
            self.stability,
            self.bitmap_cvg,
            self.saved_crashes,
            self.saved_hangs,
            self.last_find.as_secs(),
            self.last_crash.as_secs(),
            self.last_hang.as_secs(),
            self.execs_since_crash,
            self.exec_timeout,
            self.slowest_exec_ms,
            self.peak_rss_mb,
            self.cpu_affinity,
            self.edges_found,
            self.total_edges,
            self.var_byte_count,
            self.havoc_expansion,
            self.auto_dict_entries,
            self.testcache_size,
            self.testcache_count,
            self.testcache_evict,
            self.afl_banner,
            self.afl_version,
            self.target_mode,
            self.command_line
        )
    }
}
