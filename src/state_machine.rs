use crate::states::{H1Session, H1State, InterceptState, ProxyState, ShutdownState, UpstreamState};

/// Describes what the driver should do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextStep {
    Continue,
    Completed,
    Error(&'static str),
}

/// Drives the simplified proxy pipeline described in STATE_DESIGN.md.
pub struct ProxyDriver {
    state: ProxyState,
    h1_session: H1Session,
    steps: usize,
}

impl ProxyDriver {
    pub fn new() -> Self {
        Self {
            state: ProxyState::TransportBootstrap,
            h1_session: H1Session::new(),
            steps: 0,
        }
    }

    pub fn current_state(&self) -> ProxyState {
        self.state.clone()
    }

    pub fn step(&mut self) -> NextStep {
        self.steps += 1;
        let current = self.state.clone();
        match current {
            ProxyState::TransportBootstrap => {
                self.state = ProxyState::TlsHandshake;
                NextStep::Continue
            }
            ProxyState::TransportIo => {
                self.state = ProxyState::TlsHandshake;
                NextStep::Continue
            }
            ProxyState::TlsHandshake => {
                self.state = ProxyState::ProtocolSelect;
                NextStep::Continue
            }
            ProxyState::ProtocolSelect => {
                self.state = ProxyState::ConnectionReady;
                NextStep::Continue
            }
            ProxyState::ConnectionReady => {
                self.state = ProxyState::H1Session(H1State::RequestHeaders);
                NextStep::Continue
            }
            ProxyState::H1Session(H1State::RequestHeaders) => {
                self.h1_session.mark_headers_parsed(256);
                self.state = ProxyState::H1Session(H1State::RequestBody);
                NextStep::Continue
            }
            ProxyState::H1Session(H1State::RequestBody) => {
                let allocated = unsafe { self.h1_session.allocate_body(512) };
                if !allocated {
                    return NextStep::Error("body allocation failed");
                }
                self.h1_session.mark_body_parsed(512);
                self.state = ProxyState::H1Session(H1State::RequestReadyForController);
                NextStep::Continue
            }
            ProxyState::H1Session(H1State::RequestReadyForController) => {
                self.state = ProxyState::Intercept(InterceptState::Pipeline);
                NextStep::Continue
            }
            ProxyState::H1Session(H1State::DispatchToUpstream) => {
                self.state = ProxyState::Upstream(UpstreamState::ResolveDns);
                NextStep::Continue
            }
            ProxyState::H1Session(H1State::ResponseHeaders) => {
                self.h1_session.mark_headers_parsed(64);
                self.state = ProxyState::H1Session(H1State::ResponseBody);
                NextStep::Continue
            }
            ProxyState::H1Session(H1State::ResponseBody) => {
                unsafe {
                    self.h1_session.release_body();
                }
                self.state = ProxyState::H1Session(H1State::ResponseComplete);
                NextStep::Continue
            }
            ProxyState::H1Session(H1State::ResponseComplete) => {
                self.state = ProxyState::Shutdown(ShutdownState::GracefulDrain);
                NextStep::Continue
            }
            ProxyState::H2Session(_) => NextStep::Error("h2 pipeline not implemented"),
            ProxyState::Intercept(InterceptState::Pipeline) => {
                self.state = ProxyState::H1Session(H1State::DispatchToUpstream);
                NextStep::Continue
            }
            ProxyState::Intercept(InterceptState::Drop) => NextStep::Error("connection dropped"),
            ProxyState::Upstream(state) => match state {
                UpstreamState::ResolveDns => {
                    self.state = ProxyState::Upstream(UpstreamState::ConnectTcp);
                    NextStep::Continue
                }
                UpstreamState::ConnectTcp => {
                    self.state = ProxyState::Upstream(UpstreamState::TlsHandshake);
                    NextStep::Continue
                }
                UpstreamState::TlsHandshake => {
                    self.state = ProxyState::Upstream(UpstreamState::DispatchRequest);
                    NextStep::Continue
                }
                UpstreamState::DispatchRequest => {
                    self.state = ProxyState::Upstream(UpstreamState::CollectResponse);
                    NextStep::Continue
                }
                UpstreamState::CollectResponse => {
                    self.state = ProxyState::H1Session(H1State::ResponseHeaders);
                    NextStep::Continue
                }
            },
            ProxyState::Shutdown(ShutdownState::GracefulDrain) => {
                self.state = ProxyState::Shutdown(ShutdownState::ShutdownBuffers);
                NextStep::Continue
            }
            ProxyState::Shutdown(ShutdownState::ShutdownBuffers) => {
                self.state = ProxyState::Shutdown(ShutdownState::Closed);
                NextStep::Continue
            }
            ProxyState::Shutdown(ShutdownState::Closed) => NextStep::Completed,
        }
    }

    pub fn run_to_completion(&mut self) -> Result<(), &'static str> {
        loop {
            match self.step() {
                NextStep::Continue => continue,
                NextStep::Completed => return Ok(()),
                NextStep::Error(err) => return Err(err),
            }
        }
    }

    pub fn steps_taken(&self) -> usize {
        self.steps
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::states::{ProxyState, ShutdownState};

    #[test]
    fn driver_reaches_completion() {
        let mut driver = ProxyDriver::new();
        assert_eq!(driver.current_state(), ProxyState::TransportBootstrap);
        driver.run_to_completion().expect("driver should succeed");
        assert_eq!(
            driver.current_state(),
            ProxyState::Shutdown(ShutdownState::Closed)
        );
        assert!(driver.steps_taken() > 0);
    }
}
