use std::{
    borrow::Cow,
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
};

use libafl::{
    corpus::{Corpus, OnDiskCorpus, Testcase},
    inputs::BytesInput,
    state::{HasCorpus, HasExecutions, HasStartTime, StdState},
    Error,
};
use libafl_bolts::{current_time, rands::StdRand};
use nix::{
    errno::Errno,
    fcntl::{Flock, FlockArg},
};

use crate::{fuzzer::LibaflFuzzState, OUTPUT_GRACE};

pub fn generate_base_filename(state: &mut LibaflFuzzState) -> String {
    let is_seed = state.must_load_initial_inputs();
    let id = state.corpus().peek_free_id();
    let name = if is_seed {
        // TODO set orig filename
        format!("id:{id:0>6},time:0,execs:0,orig:TODO",)
    } else {
        // TODO: change hardcoded values of op (operation aka stage_name) & rep (amount of stacked mutations applied)
        let src = if let Some(parent_id) = state.corpus().current() {
            parent_id.to_string()
        } else {
            String::new()
        };
        let execs = *state.executions();
        let time = (current_time() - *state.start_time()).as_secs();
        format!("id:{id:0>6},src:{src:0>6},time:{time},execs:{execs},op:havoc,rep:0",)
    };
    name
}

pub fn set_corpus_filepath(
    state: &mut LibaflFuzzState,
    testcase: &mut Testcase<BytesInput>,
    _output_dir: &PathBuf,
) -> Result<(), Error> {
    let mut name = generate_base_filename(state);
    if testcase
        .hit_feedbacks()
        .contains(&Cow::Borrowed("shared_mem"))
    {
        name = format!("{name},+cov");
    }
    *testcase.filename_mut() = Some(name);
    // We don't need to set the path since everything goes into one dir unlike with Objectives
    Ok(())
}
pub fn set_solution_filepath(
    state: &mut LibaflFuzzState,
    testcase: &mut Testcase<BytesInput>,
    output_dir: &PathBuf,
) -> Result<(), Error> {
    // sig:0SIGNAL
    // TODO: verify if 0 time if objective found during seed loading
    let mut filename = generate_base_filename(state);
    let mut dir = "crashes";
    if testcase
        .hit_objectives()
        .contains(&Cow::Borrowed("TimeoutFeedback"))
    {
        filename = format!("{filename},+tout");
        dir = "hangs";
    }
    *testcase.file_path_mut() = Some(output_dir.join(dir).join(&filename));
    *testcase.filename_mut() = Some(filename);
    Ok(())
}

// We return the File since the lock is released on drop.
pub fn check_autoresume(fuzzer_dir: &PathBuf, auto_resume: bool) -> Result<Flock<File>, Error> {
    if !fuzzer_dir.exists() {
        std::fs::create_dir_all(fuzzer_dir)?;
    }
    // lock the fuzzer dir
    let fuzzer_dir_fd = File::open(fuzzer_dir)?;
    let file = match Flock::lock(fuzzer_dir_fd, FlockArg::LockExclusiveNonblock) {
        Ok(l) => l,
        Err(err) => match err.1 {
            Errno::EWOULDBLOCK => return Err(Error::illegal_state(
                "Looks like the job output directory is being actively used by another instance",
            )),
            _ => {
                return Err(Error::illegal_state(
                    format!("Error creating lock for output dir: exit code {}", err.1).as_str(),
                ))
            }
        },
    };
    // Check if we have an existing fuzzed fuzzer_dir
    let stats_file = fuzzer_dir.join("fuzzer_stats");
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
        if !auto_resume && last_update.saturating_sub(start_time) > OUTPUT_GRACE * 60 {
            return Err(Error::illegal_state("The job output directory already exists and contains results! use AFL_AUTORESUME=true or provide \"-\" for -i "));
        }
    }
    if auto_resume {
        // TODO: once the queue stuff is implemented finish the rest of the function
        // see afl-fuzz-init.c line 1898 onwards. Gotta copy and delete shit
        // No usable test cases in './output/default/_resume'
    }
    Ok(file)
}

pub fn main_node_exists(output_dir: &PathBuf) -> Result<bool, Error> {
    let mut main_found = false;
    for entry in std::fs::read_dir(output_dir)?.filter_map(std::result::Result::ok) {
        let path = entry.path();
        if path.is_dir() && path.join("is_main_node").exists() {
            main_found = true;
            break;
        }
    }
    Ok(main_found)
}
