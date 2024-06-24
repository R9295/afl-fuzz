use libafl::{
    events::{Event, EventManagerHook},
    state::{State, Stoppable},
    Error,
};
use libafl_bolts::ClientId;

#[derive(Clone, Copy)]
pub struct LibAflFuzzEventHook {
    exit_on_solution: bool,
}

impl LibAflFuzzEventHook {
    pub fn new(exit_on_solution: bool) -> Self {
        Self { exit_on_solution }
    }
}

impl<S> EventManagerHook<S> for LibAflFuzzEventHook
where
    S: State + Stoppable,
{
    fn pre_exec(
        &mut self,
        state: &mut S,
        client_id: ClientId,
        event: &Event<S::Input>,
    ) -> Result<bool, Error> {
        match event {
            Event::Objective { .. } => {
                if self.exit_on_solution {
                    // TODO: dump state
                    *state.should_stop_mut() = true;
                }
            }
            _ => {},
        }
        Ok(true)
    }
    fn post_exec(&mut self, state: &mut S, client_id: ClientId) -> Result<bool, Error> {
        Ok(true)
    }
}
