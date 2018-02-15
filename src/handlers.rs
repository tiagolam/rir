use std::net::SocketAddr;
use futures::{self, Future, BoxFuture};
use std::sync::{mpsc, Arc, Mutex};

use rustun::{Error, HandleMessage, ErrorKind};
use rustun::message::{Request, Response, Indication};
use rustun::attribute::{Attribute};
use rustun::rfc5389;
use rustun::rfc5389::attributes::XorMappedAddress;
use rustun::rfc5389::attributes::MessageIntegrity;

use rtp::RirHandler;

/// A `HandleMessage` implementation which only handle `Binding` method.
pub struct RtpHandler {
    passwd: String,
    relay: mpsc::Sender<Vec<u8>>,
    use_candidate: Box<RirHandler + Send>,
}

#[derive(Debug)]
pub enum CallbackType {
    USE_CANDIDATE(SocketAddr),
}

impl RtpHandler {
    /// Makes a new `RtpHandler` instance.
    pub fn new(passwd: String, relay: mpsc::Sender<Vec<u8>>, callback: Box<RirHandler + Send>) -> Self {
        RtpHandler {
            passwd: passwd,
            relay: relay,
            use_candidate: callback,
        }
    }
}

impl HandleMessage for RtpHandler {
    type Method = rfc5389::methods::Binding;
    type Attribute = rfc5389::Attribute;
    type HandleCall = BoxFuture<Response<Self::Method, Self::Attribute>, ()>;
    type HandleCast = BoxFuture<(), ()>;
    type Info = ();
    fn handle_call(&mut self,
                   client: SocketAddr,
                   request: Request<Self::Method, Self::Attribute>)
                   -> Self::HandleCall {
        let request_clone = request.clone();
        let mut response = request.into_success_response();

        for attr in request_clone.attributes() {
            if attr.get_type().as_u16() == rfc5389::attributes::TYPE_USERNAME {
                response.add_attribute(attr.clone());
            } else if attr.get_type().as_u16() == rfc5389::attributes::TYPE_USE_CANDIDATE {
                self.use_candidate.handle_event(CallbackType::USE_CANDIDATE(client));
            }

        }

        response.add_attribute(XorMappedAddress::new(client));

        let response_clone = response.clone();
        response.add_attribute(MessageIntegrity::new_short_term_credential(&response_clone, &self.passwd).unwrap());

        for attr in request_clone.attributes() {
            if attr.get_type().as_u16() == rfc5389::attributes::TYPE_FINGERPRINT {
                response.add_attribute(attr.clone());
            }
        }

        futures::finished(Ok(response)).boxed()
    }
    fn handle_cast(&mut self,
                   _client: SocketAddr,
                   _message: Indication<Self::Method, Self::Attribute>)
                   -> Self::HandleCast {
        futures::finished(()).boxed()
    }
    fn handle_error(&mut self, client: SocketAddr, error: Error) {
        match *error.kind() {
            ErrorKind::Discard(ref buf) => {
                let mut tmp_buf = vec![0; buf.len()];
                tmp_buf.clone_from_slice(&buf);

                println!("Caught discard error from the client {}: {:?}", client, tmp_buf);
                self.relay.send(tmp_buf).unwrap();

                println!("After sending...");
            },
            _ => {
                println!("Cannot handle unknown error from the client {}: {}", client, error);
            },
        }
    }
}
