// Copyright (c) 2017, 2018 Tiago Lam
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

#[macro_use]
extern crate log;
extern crate log4rs;
extern crate byteorder;
extern crate chan;
extern crate rand;
extern crate time;
extern crate timer;
extern crate stringprep;
extern crate md5;
extern crate hmacsha1;
extern crate crc;

pub mod rtp;
pub mod stun;
pub mod handlers;
