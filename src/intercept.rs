use crate::canonical::{CanonicalRequest, CanonicalResponse};

/// Decision that the intercept controller drives before progressing down the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptDecision {
    Continue,
    Drop,
}

/// Controller interface that can mutate canonical requests/responses before they hit the network.
pub trait InterceptController {
    fn intercept_request(&self, request: &mut CanonicalRequest) -> InterceptDecision;
    fn intercept_response(&self, response: &mut CanonicalResponse) -> InterceptDecision;
}

/// Basic controller used when no bespoke logic is attached to the driver.
pub struct NoopController;

impl InterceptController for NoopController {
    fn intercept_request(&self, _: &mut CanonicalRequest) -> InterceptDecision {
        InterceptDecision::Continue
    }

    fn intercept_response(&self, _: &mut CanonicalResponse) -> InterceptDecision {
        InterceptDecision::Continue
    }
}
