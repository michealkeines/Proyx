use crate::{ConnectionState, MitmProxy};
use http_body_util::{BodyExt, combinators::BoxBody};
use hyper::{
    Method, Request, Response, Uri,
    body::{Body, Incoming},
    service::HttpService,
};
use std::{borrow::Borrow, pin::Pin, ptr, sync::Arc};
use tokio::sync::oneshot;
use tracing::info;

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
        };
        connection.metadata = Some(metadata.clone());
        let ui_state = connection.proxy.ui_state.clone();
        let connection_id = ui_state
            .register_connection(metadata.method.to_string(), metadata.uri.to_string())
            .await;
        connection.connection_id = Some(connection_id);

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
    resume: oneshot::Receiver<()>,
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
        let _ = self.resume.await;

        let request = self
            .request
            .expect("await resume state keeps the request alive");
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
        let boxed = response.map(|body| body.boxed());

        Ok(Execution::Ready(boxed))
    }
}
