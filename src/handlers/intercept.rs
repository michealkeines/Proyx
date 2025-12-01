use crate::{connection::Connection, fsm::NextStep, states::InterceptState};

pub async unsafe fn intercept_handler(_: &mut Connection, _: InterceptState) -> NextStep {
    println!("[INTERCEPT] Not implemented");
    NextStep::Close
}
