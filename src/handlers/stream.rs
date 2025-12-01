use crate::{connection::Connection, fsm::NextStep, states::StreamState};

pub async unsafe fn stream_handler(_: &mut Connection, _: StreamState) -> NextStep {
    NextStep::Close
}
