use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, Testcase},
    inputs::BytesInput,
    state::{HasCorpus, HasExecutions, HasStartTime, StdState},
    Error,
};
use libafl_bolts::{current_time, rands::StdRand};

pub fn generate_base_filename(
    state: &mut StdState<BytesInput, InMemoryCorpus<BytesInput>, StdRand, OnDiskCorpus<BytesInput>>,
) -> Result<String, Error> {
    let time = if state.must_load_initial_inputs() {
        0
    } else {
        (current_time() - *state.start_time()).as_secs()
    };
    let id = state.corpus().peek_free_id();
    let src = if let Some(parent_id) = state.corpus().current() {
        parent_id.to_string()
    } else {
        String::new()
    };
    let execs = *state.executions();
    // TODO: change hardcoded values of op (operation aka stage_name) & rep (amount of stacked mutations applied)
    let name = format!("id:{id:0>6};src:{src:0>6};time:{time};execs:{execs};op:havoc;rep:0",);
    Ok(name)
}
