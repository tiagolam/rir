extern crate rir;
#[macro_use]
extern crate log;
extern crate log4rs;

use std::thread;
use std::str::FromStr;
use std::net::{UdpSocket, SocketAddr};

use rir::rtp::{RtpSession, RtpPkt, RtpHeader};

#[test]
fn test_connect() {

    // Set up the local socket
    let local_addr =  FromStr::from_str("127.0.0.1").unwrap();
    let bind_socket = SocketAddr::new(local_addr, 0);
    let conn = UdpSocket::bind(bind_socket);

    log4rs::init_file("config/log4rs.yaml", Default::default()).unwrap();
    info!("Firing up!...");

    let mut rtp_stream = RtpSession::connect_to(conn.unwrap(), SocketAddr::new(local_addr, 32000));

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

    while true {
        rtp_stream.read(rtp_pkt);
        //thread::sleep_ms(50);
    }
}

