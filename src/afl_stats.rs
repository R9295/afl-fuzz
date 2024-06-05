/// Stage for stats generation
#[allow(clippy::module_name_repetitions)]
use core::{marker::PhantomData, time::Duration};
use std::borrow::Cow;

use libafl_bolts::{current_time, AsIter, Named};
use serde_json::json;

use libafl::{
    corpus::{Corpus, HasCurrentCorpusId}, events::EventFirer, feedbacks::{HasObserverHandle, MapFeedbackMetadata}, observers::MapObserver, schedulers::minimizer::IsFavoredMetadata, stages::Stage, state::{HasCorpus, HasExecutions, HasImported, HasLastReportTime, HasStartTime, UsesState}, Error, HasMetadata, HasNamedMetadata
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
    /// name of the map observer
    map_name: Cow<'static, str>,
    // the number of testcases that have been fuzzed
    has_fuzzed_size: usize,
    // the number of "favored" testcases
    is_favored_size: usize,
    // the number of testcases found by itself
    own_finds_size: usize,
    // the number of testcases imported by other fuzzers
    imported_size: usize,
    // the last time that we report all stats
    last_report_time: Duration,
    // the interval that we report all stats
    stats_report_interval: Duration,

    phantom: PhantomData<(E, EM, Z)>,
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
        HasImported + HasCorpus + HasMetadata + HasStartTime + HasLastReportTime + HasExecutions + HasNamedMetadata,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        _manager: &mut EM,
    ) -> Result<(), Error> {
        // TODO: check interval 
        let Some(corpus_idx) = state.current_corpus_id()? else {
            return Err(Error::illegal_state(
                "state is not currently processing a corpus index",
            ));
        };
        {
            let testcase = state.corpus().get(corpus_idx)?.borrow();
            if testcase.scheduled_count() == 0 {
                self.has_fuzzed_size += 1;
                if testcase.has_metadata::<IsFavoredMetadata>() {
                    self.is_favored_size += 1;
                }
            }
        }
        let corpus_size = state.corpus().count();
        let pending_total = corpus_size - self.has_fuzzed_size;
        let pending_favs = corpus_size - self.is_favored_size;
        self.imported_size = *state.imported();
        self.own_finds_size = corpus_size - self.imported_size;
        let map_metadata = state.named_metadata_map().get::<MapFeedbackMetadata<u8>>("shared_mem").unwrap();
        let edges_found = map_metadata.num_covered_map_indexes;
        // TODO: can be hardcoded if not dynamic!
        let total_edges = map_metadata.history_map.len();
        /* if state.has_metadata::<UnstableEntriesMetadata>() {
            let unstable_entries = state
                .metadata_map()
                .get::<UnstableEntriesMetadata>()
                .unwrap();
            let unstable = unstable_entries.unstable_entries().len().saturating_div(rhs)

        } */
        let cur = current_time();
        if cur.checked_sub(self.last_report_time).unwrap_or_default() > self.stats_report_interval {
            let stats = json!({
                "start_time": state.start_time(),
                "last_update": state.last_report_time().unwrap_or_default().as_secs(), // TODO
                "run_time": "",
                "fuzzer_pid": "",
                "cycles_done": "",
                "cycles_wo_finds": "",
                "time_wo_finds": "",
                "execs_done": state.executions(),
                "exec_per_sec": "",
                "execs_ps_last_min": "",
                "corpus_count": corpus_size,
                "corpus_favored": "",
                "corpus_imported": self.imported_size,
                "corpus_variable": "", // number of test cases showing variable behavior
                "max_depth": "",
                "cur_item": "",
                "pendinv_favs": pending_favs,
                "pending_total": pending_total,
                "stability": "",
                "bitmap_cvg": "",
                "saved_crashes": "",
                "saved_hangs": "",
                "last_find": "",
                "last_crash": "",
                "last_hang": "",
                "execs_since_crash": "", // execs since the last crash was found
                "exec_timeout":"", //configured timeout
                "slowest_exec_ms": "", // real time of the slowest execution in ms
                "peak_rss_mb": "", // max rss usage reached during fuzzing in MB
                "edges_found": edges_found,
                "total_edges": total_edges,
                "var_byte_count": "", //  how many edges are non-deterministic
                "afl_banner": "", // binary
                "afl_version": "",
                "target_mode": "", //  how many edges are non-deterministic
                "command_line": "" //full command line used for the fuzzing session

            });
            self.last_report_time = cur;
        }

        Ok(())
    }

    #[inline]
    fn restart_progress_should_run(&mut self, _state: &mut Self::State) -> Result<bool, Error> {
        // Not running the target so we wont't crash/timeout and, hence, don't need to restore anything
        Ok(true)
    }

    #[inline]
    fn clear_restart_progress(&mut self, _state: &mut Self::State) -> Result<(), Error> {
        // Not running the target so we wont't crash/timeout and, hence, don't need to restore anything
        Ok(())
    }
}

impl<E, EM, Z> AflStatsStage<E, EM, Z>
where
    E: UsesState,
    EM: EventFirer<State = E::State>,
    Z: UsesState<State = E::State>,
    E::State: HasImported + HasCorpus + HasMetadata,
{
    /// create a new instance of the [`AflStatsStage`]
    #[must_use]
    pub fn new(interval: Duration, map_name: Cow<'static, str>) -> Self 
    {
        Self {
            map_name,
            stats_report_interval: interval,
            has_fuzzed_size: 0,
            is_favored_size: 0,
            own_finds_size: 0,
            imported_size: 0,
            last_report_time: current_time(),
            phantom: PhantomData,
        }
    }
}
