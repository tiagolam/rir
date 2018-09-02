// Copyright (c) 2018 Tiago Lam
//
// This file is part of the RiR library.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::net::SocketAddr;

use rtp::RirHandler;

/// A `HandleMessage` implementation which only handle `Binding` method.
pub struct RtpHandler {
    callback: Box<RirHandler + Send + Sync>,
}

#[derive(Debug)]
pub enum CallbackType {
    UseCandidate(SocketAddr),
}

impl RtpHandler {
    /// Makes a new `RtpHandler` instance.
    pub fn new(callback: Box<RirHandler + Send + Sync>) -> Self {
        RtpHandler {
            callback: callback,
        }
    }

    pub fn use_candidate(&self, sock: SocketAddr) {
        self.callback.handle_event(CallbackType::UseCandidate(sock));
    }
}
