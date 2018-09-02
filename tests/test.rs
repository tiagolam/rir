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

extern crate rir;
#[macro_use]
extern crate log;
extern crate log4rs;

use std::thread;
use std::str::FromStr;
use std::net::{UdpSocket, SocketAddr};
use std::io::prelude::*;
use std::fs::File;

use rir::rtp::{RtpSession, RtpPkt, RtpHeader};

#[test]
fn test_sending() {

    let mut f = File::open("./tests/hello_world.txt").unwrap();

    // Set up the local socket
    let local_addr =  FromStr::from_str("127.0.0.1").unwrap();
    let rtp_socket = SocketAddr::new(local_addr, 0);
    let rtcp_socket = SocketAddr::new(local_addr, 0);

    log4rs::init_file("config/log4rs.yaml", Default::default()).unwrap();
    info!("Running the send only test...");

    // Change 32000 port to point to the RTP port on the receiving side
    let rtp_stream = RtpSession::connect_to_simple(rtp_socket, rtcp_socket, SocketAddr::new(local_addr, 32000));

    let v = vec![];

    let mut rtp_pkt = &mut RtpPkt {
        header: RtpHeader {
            version: 2,
            padding: 0,
            ext: 0,
            cc: 0,
            marker: 0,
            payload_type: 0,
            seq_number: 0,
            timestamp: 0,
            ssrc: 0123456789,
            csrc: v,
        },
        payload: vec![],
    };

    let mut buffer: [u8; 1400] = [0; 1400];
    let mut seq = 0;
    let mut ts = 0;

    while let Ok(x) = f.read(&mut buffer) {
        if x == 0 {
            break;
        }

        rtp_pkt.header.seq_number = seq;
        rtp_pkt.header.timestamp = ts;

        debug!("Writing packet with payload {} and seq {}", x, seq);

        rtp_pkt.payload = vec![0; x];
        rtp_pkt.payload.clone_from_slice(&buffer[..x]);

        rtp_stream.write(rtp_pkt);
        thread::sleep_ms(160);

        ts += 160;
        if seq >= 65535 {
            seq = 0;
        } else {
            seq += 160;
        }
    }
}

#[test]
fn test_receiving() {

    // Set up the local socket
    let local_addr =  FromStr::from_str("127.0.0.1").unwrap();
    let rtp_socket = SocketAddr::new(local_addr, 0);
    let rtcp_socket = SocketAddr::new(local_addr, 0);

    log4rs::init_file("config/log4rs.yaml", Default::default()).unwrap();
    info!("Firing up!...");

    let rtp_stream = RtpSession::connect_to_simple(rtp_socket, rtcp_socket, SocketAddr::new(local_addr, 32000));

    let rtp_pkt = &mut RtpPkt {
        header: RtpHeader {
            version: 0,
            padding: 0,
            ext: 0,
            cc: 0,
            marker: 0,
            payload_type: 0,
            seq_number: 0,
            timestamp: 0,
            ssrc: 0,
            csrc: vec![],
        }, 
        payload: vec![],
    };

    loop {
        rtp_stream.read(rtp_pkt);
    }
}
