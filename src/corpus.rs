    use std::{
    borrow::Cow,
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
    time::Duration,
};

use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, Testcase},
    inputs::BytesInput,
    state::{HasCorpus, HasExecutions, HasStartTime, StdState},
    Error,
};
use libafl_bolts::{current_time, rands::StdRand};
use nix::{errno::Errno, fcntl::{Flock, FlockArg}};

use crate::{Opt, OUTPUT_GRACE};

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

// We return the File since the lock is released on drop.
pub fn check_autoresume(opt: &Opt) -> Result<Flock<File>, Error> {
    let output_dir = &opt.output_dir;
    if !output_dir.exists() {
        std::fs::create_dir_all(&output_dir)?;
    }
    // lock the output dir
    let output_dir_fd = File::open(&output_dir)?;
    let file = match Flock::lock(output_dir_fd, FlockArg::LockExclusiveNonblock) {
      Ok(l) => l,
      Err(err) => {
            match err.1 {
                Errno::EWOULDBLOCK => {
                    return Err(Error::illegal_state("Looks like the job output directory is being actively used by another instance"))
                }
                _ => {
                    return Err(Error::illegal_state(format!("Error creating lock for output dir: exit code {}", err.1).as_str()))
                }
            }
        },
    };
    // Check if we have an existing fuzzed output_dir
    let stats_file = output_dir.join("fuzzer_stats");
    if stats_file.exists() {
        let file = File::open(&stats_file).unwrap();
        let reader = BufReader::new(file);
        let mut start_time: u64 = 0;
        let mut last_update: u64 = 0;
        for (index, line) in reader.lines().enumerate() {
            match index {
                // first line is start_time
                0 => {
                    start_time = line.unwrap().split(": ").last().unwrap().parse().unwrap();
                }
                // second_line is last_update
                1 => {
                    last_update = line.unwrap().split(": ").last().unwrap().parse().unwrap();
                }
                _ => break,
            }
        }
        if !opt.auto_resume && last_update.saturating_sub(start_time) > OUTPUT_GRACE * 60 {
            return Err(Error::illegal_state("The job output directory already exists and contains results! use AFL_AUTORESUME=true or provide \"-\" for -i "));
        }
    }
    if opt.auto_resume {
        // TODO: once the queue stuff is implemented finish the rest of the function
        // see afl-fuzz-init.c line 1898 onwards. Gotta copy and delete shit
    }
    Ok(file)
}
