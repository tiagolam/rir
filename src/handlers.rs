use std::net::SocketAddr;

use rtp::RirHandler;

/// A `HandleMessage` implementation which only handle `Binding` method.
pub struct RtpHandler {
    callback: Box<RirHandler + Send + Sync>,
}

#[derive(Debug)]
pub enum CallbackType {
    USE_CANDIDATE(SocketAddr),
}

impl RtpHandler {
    /// Makes a new `RtpHandler` instance.
    pub fn new(callback: Box<RirHandler + Send + Sync>) -> Self {
        RtpHandler {
            callback: callback,
        }
    }

    pub fn use_candidate(&self, sock: SocketAddr) {
        self.callback.handle_event(CallbackType::USE_CANDIDATE(sock));
    }
}
