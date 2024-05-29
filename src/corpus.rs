use std::borrow::Cow;

use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, Testcase},
    inputs::BytesInput,
    state::{HasCorpus, HasExecutions, HasStartTime, StdState},
    Error,
};
use libafl_bolts::{current_time, rands::StdRand};

pub fn generate_base_filename(
    state: &mut StdState<BytesInput, InMemoryCorpus<BytesInput>, StdRand, OnDiskCorpus<BytesInput>>,
) -> String {
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
    name
}

#[allow(clippy::unnecessary_wraps)]
pub fn generate_corpus_filename(
    state: &mut StdState<BytesInput, InMemoryCorpus<BytesInput>, StdRand, OnDiskCorpus<BytesInput>>,
    testcase: &mut Testcase<BytesInput>,
) -> Result<String, Error> {
    let mut name = generate_base_filename(state);
    if testcase
        .hit_feedbacks()
        .contains(&Cow::Borrowed("shared_mem"))
    {
        name = format!("{name},+cov");
    }
    Ok(name)
}
#[allow(clippy::unnecessary_wraps)]
pub fn generate_solution_filename(
    state: &mut StdState<BytesInput, InMemoryCorpus<BytesInput>, StdRand, OnDiskCorpus<BytesInput>>,
    testcase: &mut Testcase<BytesInput>,
) -> Result<String, Error> {
    // sig:0SIGNAL
    // TODO: verify if 0 time if objective found during seed loading
    let mut name = generate_base_filename(state);
    if testcase
        .hit_objectives()
        .contains(&Cow::Borrowed("TimeoutFeedback"))
    {
        name = format!("{name},+tout");
    }
    Ok(name)
}
