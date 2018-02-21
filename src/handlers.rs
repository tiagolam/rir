use std::net::SocketAddr;
use std::sync::{mpsc, Arc, Mutex};

use rtp::RirHandler;

/// A `HandleMessage` implementation which only handle `Binding` method.
pub struct RtpHandler {
    passwd: String,
    relay: Arc<Mutex<mpsc::Sender<Vec<u8>>>>,
    use_candidate: Box<RirHandler + Send>,
}

#[derive(Debug)]
pub enum CallbackType {
    USE_CANDIDATE(SocketAddr),
}

impl RtpHandler {
    /// Makes a new `RtpHandler` instance.
    pub fn new(passwd: String, relay: Arc<Mutex<mpsc::Sender<Vec<u8>>>>, callback: Box<RirHandler + Send>) -> Self {
        RtpHandler {
            passwd: passwd,
            relay: relay,
            use_candidate: callback,
        }
    }
}
