use crate::canonical::{CanonicalRequest, CanonicalResponse};
use crate::intercept::{InterceptController, InterceptDecision, NoopController};
use crate::states::{
    H1Session, H1State, InterceptPhase, InterceptState, ProxyState, ShutdownState, UpstreamState,
};

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
    controller: Box<dyn InterceptController>,
    pending_request: Option<CanonicalRequest>,
}

impl ProxyDriver {
    /// Construct a driver that uses the default (noop) intercept controller.
    pub fn new() -> Self {
        Self::with_controller(NoopController)
    }

    /// Construct a driver with a custom intercept controller.
    pub fn with_controller(controller: impl InterceptController + 'static) -> Self {
        Self {
            state: ProxyState::TransportBootstrap,
            h1_session: H1Session::new(),
            steps: 0,
            controller: Box::new(controller),
            pending_request: None,
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
                let canonical = CanonicalRequest::from_session(&self.h1_session);
                self.pending_request = Some(canonical);
                self.state =
                    ProxyState::Intercept(InterceptState::Pipeline(InterceptPhase::Request));
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
            ProxyState::Intercept(InterceptState::Pipeline(phase)) => match phase {
                InterceptPhase::Request => {
                    if let Some(mut request) = self.pending_request.take() {
                        match self.controller.intercept_request(&mut request) {
                            InterceptDecision::Continue => {
                                self.state = ProxyState::H1Session(H1State::DispatchToUpstream);
                            }
                            InterceptDecision::Drop => {
                                self.state = ProxyState::Intercept(InterceptState::Drop);
                            }
                        }
                        NextStep::Continue
                    } else {
                        NextStep::Error("missing canonical request")
                    }
                }
                InterceptPhase::Response => {
                    let mut response = CanonicalResponse::from_session(&self.h1_session);
                    match self.controller.intercept_response(&mut response) {
                        InterceptDecision::Continue => {
                            self.state = ProxyState::H1Session(H1State::ResponseHeaders);
                        }
                        InterceptDecision::Drop => {
                            self.state = ProxyState::Intercept(InterceptState::Drop);
                        }
                    }
                    NextStep::Continue
                }
            },
            ProxyState::Intercept(InterceptState::Drop) => {
                self.pending_request.take();
                unsafe {
                    self.h1_session.release_body();
                }
                self.state = ProxyState::Shutdown(ShutdownState::GracefulDrain);
                NextStep::Continue
            }
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
                    self.state =
                        ProxyState::Intercept(InterceptState::Pipeline(InterceptPhase::Response));
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
    use crate::intercept::InterceptController;
    use crate::states::{ProxyState, ShutdownState};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct CountingController {
        counter: Arc<AtomicUsize>,
    }

    impl CountingController {
        fn new(counter: Arc<AtomicUsize>) -> Self {
            Self { counter }
        }
    }

    impl InterceptController for CountingController {
        fn intercept_request(&self, _: &mut CanonicalRequest) -> InterceptDecision {
            self.counter.fetch_add(1, Ordering::SeqCst);
            InterceptDecision::Continue
        }

        fn intercept_response(&self, _: &mut CanonicalResponse) -> InterceptDecision {
            InterceptDecision::Continue
        }
    }

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

    #[test]
    fn intercept_request_is_called() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut driver = ProxyDriver::with_controller(CountingController::new(counter.clone()));
        driver.run_to_completion().expect("driver should succeed");
        assert!(counter.load(Ordering::SeqCst) > 0);
    }
}
