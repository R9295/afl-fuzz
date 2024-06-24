use libafl::schedulers::powersched::PowerSchedule;

/// The power schedule to use; Copied so we can use `clap::ValueEnum`
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerScheduleCustom {
    /// The `explore` power schedule
    Explore,
    /// The `exploit` power schedule
    Exploit,
    /// The `fast` power schedule
    Fast,
    /// The `coe` power schedule
    Coe,
    /// The `lin` power schedule
    Lin,
    /// The `quad` power schedule
    Quad,
}

impl From<PowerScheduleCustom> for PowerSchedule {
    fn from(val: PowerScheduleCustom) -> Self {
        match val {
            PowerScheduleCustom::Explore => PowerSchedule::EXPLORE,
            PowerScheduleCustom::Coe => PowerSchedule::COE,
            PowerScheduleCustom::Lin => PowerSchedule::LIN,
            PowerScheduleCustom::Fast => PowerSchedule::FAST,
            PowerScheduleCustom::Quad => PowerSchedule::QUAD,
            PowerScheduleCustom::Exploit => PowerSchedule::EXPLOIT,
        }
    }
}
#[macro_export]
macro_rules! run_fuzzer_with_stage {
    ($opt: expr, $fuzzer: expr, $stages:expr, $executor: expr, $state: expr, $mgr: expr) => {
        if $opt.bench_just_one {
            $fuzzer
                .fuzz_loop_for($stages, $executor, $state, $mgr, 1)
                .expect("Error benching just once");
        } else if $opt.bench_until_crash {
            loop {
                $fuzzer
                    .fuzz_loop_for($stages, $executor, $state, $mgr, 1)
                    .expect("Error benching just once");
            }
        } else {
            $fuzzer
                .fuzz_loop($stages, $executor, $state, $mgr)
                .expect("Error in the fuzzing loop");
        }
    };
}
