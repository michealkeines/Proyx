use crate::{
    ConnectionState, MitmProxy,
    proxy_state::{HeaderEntry, InterceptDecision, RequestDetails, ResponseDetails},
};
use http_body_util::{BodyExt, Empty, combinators::BoxBody};
use hyper::{
    Method, Request, Response, StatusCode, Uri,
    body::{Body, Incoming},
    header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, HeaderName},
    service::HttpService,
};
use std::{borrow::Borrow, pin::Pin, ptr, sync::Arc};
use tokio::sync::oneshot;
use tracing::{info, warn};

type BoxedResponse<S> = Response<
    BoxBody<
        <<S as HttpService<Incoming>>::ResBody as Body>::Data,
        <<S as HttpService<Incoming>>::ResBody as Body>::Error,
    >,
>;

/// Drive a lightweight nginx-style state machine for every non-CONNECT request.
pub(crate) async fn process_request<I, S>(
    proxy: Arc<MitmProxy<I>>,
    service: S,
    request: Request<Incoming>,
) -> Result<BoxedResponse<S>, <S as HttpService<Incoming>>::Error>
where
    I: Borrow<rcgen::Issuer<'static, rcgen::KeyPair>> + Send + Sync + 'static,
    S: HttpService<Incoming> + Clone + Send + 'static,
    <S as HttpService<Incoming>>::Future: Send,
    <<S as HttpService<Incoming>>::ResBody as Body>::Data: Send,
    <<S as HttpService<Incoming>>::ResBody as Body>::Error:
        Into<Box<dyn std::error::Error + Send + Sync>>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
    StateDriver::new(proxy, service, request).run().await
}

struct StateDriver<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming> + Clone + Send + 'static,
    <S as HttpService<Incoming>>::Future: Send,
    <<S as HttpService<Incoming>>::ResBody as Body>::Data: Send,
    <<S as HttpService<Incoming>>::ResBody as Body>::Error:
        Into<Box<dyn std::error::Error + Send + Sync>>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
    connection: *mut Connection<I, S>,
    dropped: bool,
}

unsafe impl<I, S> Send for StateDriver<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming> + Clone + Send + 'static,
    <S as HttpService<Incoming>>::Future: Send,
    <<S as HttpService<Incoming>>::ResBody as Body>::Data: Send,
    <<S as HttpService<Incoming>>::ResBody as Body>::Error:
        Into<Box<dyn std::error::Error + Send + Sync>>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
}

impl<I, S> StateDriver<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming> + Clone + Send + 'static,
    <S as HttpService<Incoming>>::Future: Send,
    <<S as HttpService<Incoming>>::ResBody as Body>::Data: Send,
    <<S as HttpService<Incoming>>::ResBody as Body>::Error:
        Into<Box<dyn std::error::Error + Send + Sync>>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
    fn new(proxy: Arc<MitmProxy<I>>, service: S, request: Request<Incoming>) -> Self {
        let connection = Connection::new(proxy, service, request);
        Self {
            connection: Box::into_raw(Box::new(connection)),
            dropped: false,
        }
    }

    async fn run(mut self) -> Result<BoxedResponse<S>, <S as HttpService<Incoming>>::Error> {
        let mut state = State::Request(RequestState {
            connection: self.connection,
        });

        loop {
            state = match state {
                State::Request(stage) => match stage.run().await? {
                    Execution::Continue(next) => next,
                    Execution::Ready(response) => {
                        self.drop_connection();
                        return Ok(response);
                    }
                },
                State::Intercept(stage) => match stage.run().await? {
                    Execution::Continue(next) => next,
                    Execution::Ready(response) => {
                        self.drop_connection();
                        return Ok(response);
                    }
                },
                State::AwaitResume(stage) => match stage.run().await? {
                    Execution::Continue(next) => next,
                    Execution::Ready(response) => {
                        self.drop_connection();
                        return Ok(response);
                    }
                },
                State::WaitingIo(stage) => match stage.run().await? {
                    Execution::Continue(next) => next,
                    Execution::Ready(response) => {
                        self.drop_connection();
                        return Ok(response);
                    }
                },
                State::Response(stage) => match stage.run().await? {
                    Execution::Continue(next) => next,
                    Execution::Ready(response) => {
                        self.drop_connection();
                        return Ok(response);
                    }
                },
            };
        }
    }

    fn drop_connection(&mut self) {
        if !self.dropped {
            unsafe {
                if !self.connection.is_null() {
                    drop(Box::from_raw(self.connection));
                }
            }
            self.connection = ptr::null_mut();
            self.dropped = true;
        }
    }
}

impl<I, S> Drop for StateDriver<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming> + Clone + Send + 'static,
    <S as HttpService<Incoming>>::Future: Send,
    <<S as HttpService<Incoming>>::ResBody as Body>::Data: Send,
    <<S as HttpService<Incoming>>::ResBody as Body>::Error:
        Into<Box<dyn std::error::Error + Send + Sync>>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
    fn drop(&mut self) {
        self.drop_connection();
    }
}

#[derive(Clone)]
struct RequestMetadata {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
}

fn header_entries(headers: &HeaderMap) -> Vec<HeaderEntry> {
    headers
        .iter()
        .map(|(name, value)| HeaderEntry {
            name: name.as_str().to_string(),
            value: value.to_str().unwrap_or_default().to_string(),
        })
        .collect()
}

fn header_value_u64(headers: &HeaderMap, name: &HeaderName) -> Option<u64> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
}

fn build_request_tags(metadata: &RequestMetadata) -> Vec<String> {
    let mut tags = vec![metadata.method.to_string()];
    if let Some(host) = metadata.uri.host() {
        tags.push(host.to_string());
    }
    if let Some(scheme) = metadata.uri.scheme_str() {
        tags.push(scheme.to_string());
    }
    tags
}

fn build_body_preview(metadata: &RequestMetadata, request_size: Option<u64>) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(content_type) = metadata
        .headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    {
        parts.push(format!("Content-Type: {content_type}"));
    }
    if let Some(size) = request_size {
        parts.push(format!("{size} bytes"));
    }
    (!parts.is_empty()).then(|| parts.join(" · "))
}

struct Connection<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
    proxy: Arc<MitmProxy<I>>,
    service: S,
    request: Option<Request<Incoming>>,
    response: Option<Response<<S as HttpService<Incoming>>::ResBody>>,
    metadata: Option<RequestMetadata>,
    connection_id: Option<u64>,
}

impl<I, S> Connection<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
    fn new(proxy: Arc<MitmProxy<I>>, service: S, request: Request<Incoming>) -> Self {
        Self {
            proxy,
            service,
            request: Some(request),
            response: None,
            metadata: None,
            connection_id: None,
        }
    }
}

unsafe impl<I, S> Send for Connection<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming> + Send,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
    Request<Incoming>: Send,
{
}

enum State<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
    Request(RequestState<I, S>),
    Intercept(InterceptState<I, S>),
    AwaitResume(AwaitResumeState<I, S>),
    WaitingIo(WaitingIoState<I, S>),
    Response(ResponseState<I, S>),
}

enum Execution<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
    Continue(State<I, S>),
    Ready(BoxedResponse<S>),
}

unsafe impl<I, S> Send for State<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
}

unsafe impl<I, S> Send for Execution<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
}

struct RequestState<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
    connection: *mut Connection<I, S>,
}

unsafe impl<I, S> Send for RequestState<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
}

impl<I, S> RequestState<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
    async fn run(self) -> Result<Execution<I, S>, <S as HttpService<Incoming>>::Error> {
        let connection = unsafe { &mut *self.connection };
        // Touch the proxy pointer so the connection object stays actively referenced.
        let _ = Arc::as_ptr(&connection.proxy);
        info!("RequestState enter");

        let request = connection
            .request
            .take()
            .expect("request state populates the request");
        let metadata = RequestMetadata {
            method: request.method().clone(),
            uri: request.uri().clone(),
            headers: request.headers().clone(),
        };
        connection.metadata = Some(metadata.clone());
        let ui_state = connection.proxy.ui_state.clone();
        let connection_id = ui_state
            .register_connection(metadata.method.to_string(), metadata.uri.to_string())
            .await;
        connection.connection_id = Some(connection_id);
        let request_size = header_value_u64(&metadata.headers, &CONTENT_LENGTH);
        ui_state
            .update_request_details(
                connection_id,
                RequestDetails {
                    headers: header_entries(&metadata.headers),
                    request_size,
                    tags: build_request_tags(&metadata),
                    body_preview: build_body_preview(&metadata, request_size),
                },
            )
            .await;

        Ok(Execution::Continue(State::Intercept(InterceptState {
            connection: self.connection,
            request: Some(request),
        })))
    }
}

struct InterceptState<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
    connection: *mut Connection<I, S>,
    request: Option<Request<Incoming>>,
}

unsafe impl<I, S> Send for InterceptState<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
}

impl<I, S> InterceptState<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
    async fn run(self) -> Result<Execution<I, S>, <S as HttpService<Incoming>>::Error> {
        let connection = unsafe { &mut *self.connection };
        let metadata = connection
            .metadata
            .as_ref()
            .expect("request state stores metadata");
        info!("Intercepted request {} {}", metadata.method, metadata.uri);

        let connection_id = connection
            .connection_id
            .expect("request state assigns a connection id");
        let ui_state = connection.proxy.ui_state.clone();
        ui_state
            .update_state(connection_id, ConnectionState::Intercept, None)
            .await;

        let request = self
            .request
            .expect("Intercept state keeps the request alive until handled");

        if ui_state.is_live_intercept() {
            let resume = ui_state.wait_for_resume(connection_id).await;
            return Ok(Execution::Continue(State::AwaitResume(AwaitResumeState {
                connection: self.connection,
                request: Some(request),
                resume,
                connection_id,
            })));
        }

        let pending = connection.service.call(request);
        let waiting = WaitingIoState {
            connection: self.connection,
            pending: Box::pin(pending),
            connection_id,
        };
        ui_state
            .update_state(connection_id, ConnectionState::WaitingIo, None)
            .await;

        Ok(Execution::Continue(State::WaitingIo(waiting)))
    }
}

struct AwaitResumeState<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
    connection: *mut Connection<I, S>,
    request: Option<Request<Incoming>>,
    resume: oneshot::Receiver<InterceptDecision>,
    connection_id: u64,
}

unsafe impl<I, S> Send for AwaitResumeState<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
}

impl<I, S> AwaitResumeState<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
    async fn run(self) -> Result<Execution<I, S>, <S as HttpService<Incoming>>::Error> {
        let connection = unsafe { &mut *self.connection };
        let decision = match self.resume.await {
            Ok(value) => value,
            Err(_) => {
                warn!(
                    "Intercept waiter dropped before decision for request {}",
                    self.connection_id
                );
                InterceptDecision::Drop
            }
        };

        match decision {
            InterceptDecision::Resume => {
                let request = self
                    .request
                    .expect("await resume state keeps the request alive");
                let _ = connection
                    .proxy
                    .ui_state
                    .clone()
                    .take_intercept_modification(self.connection_id)
                    .await;
                let pending = connection.service.call(request);
                let waiting = WaitingIoState {
                    connection: self.connection,
                    pending: Box::pin(pending),
                    connection_id: self.connection_id,
                };
                let ui_state = connection.proxy.ui_state.clone();
                ui_state
                    .update_state(self.connection_id, ConnectionState::WaitingIo, None)
                    .await;

                Ok(Execution::Continue(State::WaitingIo(waiting)))
            }
            InterceptDecision::Drop => {
                let ui_state = connection.proxy.ui_state.clone();
                ui_state
                    .update_state(self.connection_id, ConnectionState::Response, Some(499))
                    .await;
                let body = Empty::<<<S as HttpService<Incoming>>::ResBody as Body>::Data>::new()
                    .map_err(|never| match never {})
                    .boxed();
                let response = Response::builder()
                    .status(StatusCode::from_u16(499).unwrap())
                    .body(body)
                    .expect("failed to build drop response");
                Ok(Execution::Ready(response))
            }
        }
    }
}

struct WaitingIoState<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
    connection: *mut Connection<I, S>,
    pending: Pin<Box<<S as HttpService<Incoming>>::Future>>,
    connection_id: u64,
}

unsafe impl<I, S> Send for WaitingIoState<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
    <S as HttpService<Incoming>>::Future: Send,
{
}

impl<I, S> WaitingIoState<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
    async fn run(self) -> Result<Execution<I, S>, <S as HttpService<Incoming>>::Error> {
        let response = self.pending.await?;
        let connection = unsafe { &mut *self.connection };
        connection.response = Some(response);

        if let Some(metadata) = &connection.metadata {
            info!("Response ready for {} {}", metadata.method, metadata.uri);
        }

        Ok(Execution::Continue(State::Response(ResponseState {
            connection: self.connection,
            connection_id: self.connection_id,
        })))
    }
}

struct ResponseState<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
    connection: *mut Connection<I, S>,
    connection_id: u64,
}

unsafe impl<I, S> Send for ResponseState<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
}

impl<I, S> ResponseState<I, S>
where
    I: Send + Sync + 'static,
    S: HttpService<Incoming>,
    <S as HttpService<Incoming>>::ResBody: Send + Sync + 'static,
{
    async fn run(self) -> Result<Execution<I, S>, <S as HttpService<Incoming>>::Error> {
        let connection = unsafe { &mut *self.connection };
        let response = connection
            .response
            .take()
            .expect("waiting IO produces a response");
        if let Some(metadata) = connection.metadata.take() {
            info!(
                "Response state for {} {} -> {}",
                metadata.method,
                metadata.uri,
                response.status()
            );
        }
        let status = response.status().as_u16();
        let ui_state = connection.proxy.ui_state.clone();
        ui_state
            .update_state(self.connection_id, ConnectionState::Response, Some(status))
            .await;
        let response_headers = header_entries(response.headers());
        let response_size = header_value_u64(response.headers(), &CONTENT_LENGTH);
        ui_state
            .update_response_details(
                self.connection_id,
                ResponseDetails {
                    headers: response_headers,
                    response_size,
                    duration_ms: None,
                },
            )
            .await;
        let boxed = response.map(|body| body.boxed());

        Ok(Execution::Ready(boxed))
    }
}
