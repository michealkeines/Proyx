use std::{
    alloc::{Layout, alloc_zeroed, dealloc},
    ptr::NonNull,
};

const H1_HEADERS_CAP: usize = 64 * 1024;
const H1_BODY_MAX: usize = 64 * 1024;
const RAW_ALIGN: usize = 32;

/// Small helper that keeps ownership of the raw buffers that `H1Session` manipulates.
pub struct H1Session {
    headers: NonNull<u8>,
    headers_cap: usize,
    body: Option<NonNull<u8>>,
    body_cap: usize,
    headers_len: usize,
    body_len: usize,
}

impl H1Session {
    pub fn new() -> Self {
        let layout = Layout::from_size_align(H1_HEADERS_CAP, RAW_ALIGN)
            .expect("state buffers use a fixed alignment");
        let raw = unsafe { alloc_zeroed(layout) };
        let headers = NonNull::new(raw).expect("failed to allocate h1 headers buffer");

        Self {
            headers,
            headers_cap: H1_HEADERS_CAP,
            body: None,
            body_cap: 0,
            headers_len: 0,
            body_len: 0,
        }
    }

    pub unsafe fn allocate_body(&mut self, len: usize) -> bool {
        if len == 0 || len > H1_BODY_MAX {
            return false;
        }

        if let Some(ptr) = self.body.take() {
            let layout = Layout::from_size_align(self.body_cap, RAW_ALIGN)
                .expect("body layout already validated");
            unsafe {
                dealloc(ptr.as_ptr(), layout);
            }
        }

        let layout = match Layout::from_size_align(len, RAW_ALIGN) {
            Ok(layout) => layout,
            Err(_) => return false,
        };

        let raw = unsafe { alloc_zeroed(layout) };
        let body = match NonNull::new(raw) {
            Some(ptr) => ptr,
            None => return false,
        };

        self.body = Some(body);
        self.body_cap = len;
        self.body_len = len;
        true
    }

    pub fn headers_ptr(&self) -> NonNull<u8> {
        self.headers
    }

    pub fn headers_capacity(&self) -> usize {
        self.headers_cap
    }

    pub fn headers_length(&self) -> usize {
        self.headers_len
    }

    pub fn body_ptr(&self) -> Option<NonNull<u8>> {
        self.body
    }

    pub fn body_capacity(&self) -> usize {
        self.body_cap
    }

    pub fn body_length(&self) -> usize {
        self.body_len
    }

    pub fn mark_headers_parsed(&mut self, len: usize) {
        self.headers_len = len.min(self.headers_cap);
    }

    pub fn mark_body_parsed(&mut self, len: usize) {
        self.body_len = len.min(self.body_cap);
    }

    pub unsafe fn release_body(&mut self) {
        if let Some(ptr) = self.body.take() {
            let layout =
                Layout::from_size_align(self.body_cap, RAW_ALIGN).expect("body layout consistent");
            unsafe {
                dealloc(ptr.as_ptr(), layout);
            }
            self.body_cap = 0;
            self.body_len = 0;
        }
    }
}

impl Drop for H1Session {
    fn drop(&mut self) {
        unsafe {
            let layout = Layout::from_size_align(self.headers_cap, RAW_ALIGN)
                .expect("header layout consistent");
            dealloc(self.headers.as_ptr(), layout);

            if let Some(body_ptr) = self.body {
                let layout = Layout::from_size_align(self.body_cap, RAW_ALIGN)
                    .expect("body layout consistent");
                dealloc(body_ptr.as_ptr(), layout);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyState {
    TransportBootstrap,
    TransportIo,
    TlsHandshake,
    ProtocolSelect,
    ConnectionReady,
    H1Session(H1State),
    H2Session(H2State),
    Intercept(InterceptState),
    Upstream(UpstreamState),
    Shutdown(ShutdownState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H1State {
    RequestHeaders,
    RequestBody,
    RequestReadyForController,
    DispatchToUpstream,
    ResponseHeaders,
    ResponseBody,
    ResponseComplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2State {
    Bootstrap,
    ClientFrameParse,
    BuildCanonicalRequest,
    RequestQueueEnqueue,
    ControllerHook,
    DispatchToUpstream,
    UpstreamFrameCollect,
    ResponseDispatch,
    TransportWait,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptPhase {
    Request,
    Response,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterceptState {
    Pipeline(InterceptPhase),
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamState {
    ResolveDns,
    ConnectTcp,
    TlsHandshake,
    DispatchRequest,
    CollectResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownState {
    GracefulDrain,
    ShutdownBuffers,
    Closed,
}
