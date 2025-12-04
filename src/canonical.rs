use crate::states::H1Session;
use std::ptr::NonNull;

/// A canonical representation of an HTTP/1 request extracted from the in-memory buffers.
pub struct CanonicalRequest {
    headers_ptr: NonNull<u8>,
    headers_len: usize,
    body_ptr: Option<NonNull<u8>>,
    body_len: usize,
}

impl CanonicalRequest {
    pub fn from_session(session: &H1Session) -> Self {
        Self {
            headers_ptr: session.headers_ptr(),
            headers_len: session.headers_length(),
            body_ptr: session.body_ptr(),
            body_len: session.body_length(),
        }
    }

    pub fn headers_ptr(&self) -> NonNull<u8> {
        self.headers_ptr
    }

    pub fn headers_length(&self) -> usize {
        self.headers_len
    }

    pub fn body_ptr(&self) -> Option<NonNull<u8>> {
        self.body_ptr
    }

    pub fn body_length(&self) -> usize {
        self.body_len
    }

    pub fn set_headers_length(&mut self, len: usize) {
        self.headers_len = len;
    }

    pub fn set_body_length(&mut self, len: usize) {
        self.body_len = len;
    }
}

/// A canonical representation of an HTTP/1 response that mirrors `CanonicalRequest`.
pub struct CanonicalResponse {
    headers_ptr: NonNull<u8>,
    headers_len: usize,
    body_ptr: Option<NonNull<u8>>,
    body_len: usize,
}

impl CanonicalResponse {
    pub fn from_session(session: &H1Session) -> Self {
        Self {
            headers_ptr: session.headers_ptr(),
            headers_len: session.headers_length(),
            body_ptr: session.body_ptr(),
            body_len: session.body_length(),
        }
    }

    pub fn headers_ptr(&self) -> NonNull<u8> {
        self.headers_ptr
    }

    pub fn headers_length(&self) -> usize {
        self.headers_len
    }

    pub fn body_ptr(&self) -> Option<NonNull<u8>> {
        self.body_ptr
    }

    pub fn body_length(&self) -> usize {
        self.body_len
    }

    pub fn set_headers_length(&mut self, len: usize) {
        self.headers_len = len;
    }

    pub fn set_body_length(&mut self, len: usize) {
        self.body_len = len;
    }
}
