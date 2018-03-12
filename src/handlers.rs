use std::net::SocketAddr;
use std::sync::{mpsc, Arc, Mutex};

use rtp::RirHandler;

/// A `HandleMessage` implementation which only handle `Binding` method.
pub struct RtpHandler {
    passwd: String,
    pub use_candidate: Box<RirHandler + Send + Sync>,
}

#[derive(Debug)]
pub enum CallbackType {
    USE_CANDIDATE(SocketAddr),
}

impl RtpHandler {
    /// Makes a new `RtpHandler` instance.
    pub fn new(passwd: String, callback: Box<RirHandler + Send + Sync>) -> Self {
        RtpHandler {
            passwd: passwd,
            use_candidate: callback,
        }
    }
}
