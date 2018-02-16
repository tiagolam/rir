// The RTP header:
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|V=2|P|X|  CC   |M|     PT      |       sequence number         |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|                           timestamp                           |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|           synchronization source (SSRC) identifier            |
//+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
//|            contributing source (CSRC) identifiers             |
//|                             ....                              |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//

#![allow(exceeding_bitshifts)]

use std::io::{Cursor};
use std::mem;
use std::net::{SocketAddr, UdpSocket};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::mpsc;
use std::time::{Instant};
use std::thread;

use byteorder::{ByteOrder, BigEndian, ReadBytesExt, WriteBytesExt};
use chan::{Receiver};
use rand::{thread_rng, Rng};
use timer::Timer;
use time::Duration;
use time;
use fibers::{Executor, InPlaceExecutor, Spawn};
use rustun::server::UdpServer;
use rustun::rfc5389::handlers::BindingHandler;

use handlers;

pub struct RtpHeader {
    pub version: u8,
    pub padding: u8,
    pub ext: u8,
    pub cc: u8,
    pub marker: u8,
    pub payload_type: u8,
    pub seq_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub csrc: Vec<u32>,
}

pub struct RtpPkt {
    pub header: RtpHeader,
    pub payload: Vec<u8>,
}

// TODO(tlam): Abstract away from UdpSocket, since the RFC doesn't tie to any
// transport protocol (such as UDP)
pub struct RtpSession {
    transport: StunWrapper,
    rtcp_stream: RtcpStream,
    //handler: Box<RirHandler + Send>
}

struct SourceState {
    max_seq: Mutex<u16>,
    cycles: Mutex<u32>,
    base_seq: Mutex<u32>,
    bad_seq: u32,
    probation: u32,
    received: Mutex<u32>,
    expected_prior: Mutex<u32>,
    received_prior: Mutex<u32>,
    transit: u32,
    jitter: Mutex<f32>,
}

//#define RTP_SEQ_MOD (1<<16)
macro_rules! RTP_SEQ_MOD {
    () => (1<<16);
}

/* Appendix A.1 */
impl SourceState {

    fn new(seq: u16) -> SourceState {
        let mut source_state = SourceState {
            max_seq: Mutex::new(0),
            cycles: Mutex::new(0),
            base_seq: Mutex::new(0),
            bad_seq: 0,
            received: Mutex::new(0),
            received_prior: Mutex::new(0),
            expected_prior: Mutex::new(0),
            probation: 2, /* MIN_SEQUENTIAL */
            transit: 0,
            jitter: Mutex::new(0.0),
        };

        source_state.init_seq(seq);
        source_state
    }

    fn init_seq(&mut self, seq: u16) {
        *self.max_seq.lock().unwrap() = seq;
        *self.cycles.lock().unwrap() = 0;
        self.bad_seq = RTP_SEQ_MOD!() + 1; /* so seq === bad_seq is false */
        *self.base_seq.lock().unwrap() = seq as u32;
        *self.received.lock().unwrap() = 0;
        *self.received_prior.lock().unwrap() = 0;
        *self.expected_prior.lock().unwrap() = 0;
    }

    fn update_seq(&mut self, seq: u16) -> bool {
        let udelta = seq - *self.max_seq.lock().unwrap();
        // TODO(tlam): This needs to become configurable.
        let MAX_DROPOUT = 3000;
        let MAX_MISORDER = 100;
        let MIN_SEQUENTIAL = 2;

        if self.probation != 0 {
            /* packet is in sequence  */
            let mut max_seq  = *self.max_seq.lock().unwrap();
            if seq == max_seq + 1 {
                self.probation -= 1;
                max_seq = seq;
                if self.probation == 0 {
                    self.init_seq(seq);
                    *self.received.lock().unwrap() += 1;

                    return true;
                }
            } else {
                self.probation = MIN_SEQUENTIAL - 1;
                max_seq = seq;
            }

            return false;
        } else if udelta < MAX_DROPOUT {
            /* in order, with permissible gap */
            if seq < *self.max_seq.lock().unwrap() {
                /*
                 * Sequence number wrapped - count another 64K cycle.
                 */
                *self.cycles.lock().unwrap() += RTP_SEQ_MOD!();
            }
            *self.max_seq.lock().unwrap() = seq;
        } else if udelta <= RTP_SEQ_MOD!() - MAX_MISORDER {
            /* the sequence number made a very large jump */
            if (seq as u32) == self.bad_seq {
                /*
                 * Two sequential packets -- assume that the other side
                 * restarted without telling us so just re-sync
                 * (i.e., pretend this was the first packet).
                 */
                 self.init_seq(seq);
            } else {
                self.bad_seq = ((seq as u32) + 1) & (RTP_SEQ_MOD!() - 1);

                return false;
            }
        } else {
            /* duplicate or reordered packets */
        }
        *self.received.lock().unwrap() += 1;

        return true;
    }
}

// TODO(tlam): Do we need a separate count for the members from the one
// already provided by arrays?
#[derive(Clone)]
pub struct RtcpStream {
    // RTCP stream socket connection 
    transport: StunWrapper,
    // Last time an RTPC packet was transmitted
    tp: Arc<Mutex<u64>>,
    // Current time
    tc: u64,
    // Next scheduled transmission time of an RTCP packet
    tn: u64,
    // Estimated number of session members at the time `tn` was last computed
    pmembers: u32,
    // Most current estimate for the number of session members
    members: Arc<Mutex<u32>>,
    // Most current estimate for the number of senders in a session
    senders: Arc<Mutex<u32>>,
    // Target RTCP bandwidth, i.e., the total bandwidth that will be used for
    // RTCP packets by all members of this session, in octets per second
    rtcp_bw: u32,
    // `True` if application has sent data since the 2nd previous RTCP report
    // was transmitted
    we_sent: Arc<Mutex<bool>>,
    // Average compound RTCP packet size, in octets, over all RTCP packets sent
    // and received by this participant
    avg_rtcp_size: Arc<Mutex<usize>>,
    // `True` if application has not sent yet sent an RTCP packet
    initial: bool,

    // List of synchronization sources
    members_table: Arc<Mutex<HashMap<u32, u64>>>,
    // List of contributing sources
    senders_table: Arc<Mutex<HashMap<u32, u64>>>,
    // List of unauthenticated sources
    unauth_table: Arc<Mutex<HashMap<u32, SourceState>>>,
    tx_timer: Arc<Mutex<Timer>>,
    // TODO(tlam): This is probably best saved as the RTP session state, instead
    // of RTCP state
    packet_count: Arc<Mutex<u32>>,
    byte_count: Arc<Mutex<u32>>,
}

trait Transport {
    fn recv(&self, payload: &mut [u8]) -> usize;

    fn send(&self, payload: &[u8]) -> usize;
}

#[derive(Clone)]
struct UdpTransport {
     // RTCP stream socket connection
    local_socket: Arc<RwLock<UdpSocket>>,
    // RTCP stream dest socket connection
    rem_socket: Arc<RwLock<SocketAddr>>,
}

impl UdpTransport {
    fn new(local_addr: UdpSocket, rem_socket: SocketAddr) -> UdpTransport {
        UdpTransport {
            local_socket: Arc::new(RwLock::new(local_addr)),
            rem_socket: Arc::new(RwLock::new(rem_socket)),
        }
    }

}

impl Transport for UdpTransport {
    fn recv(&self, payload: &mut [u8]) -> usize {
        let (size, _) = self.local_socket.read().unwrap().recv_from(payload).unwrap();

        size
    }

    fn send(&self, payload: &[u8]) -> usize {
        let lsock = self.local_socket.read().unwrap();
        lsock.send_to(payload, *(self.rem_socket.read().unwrap())).unwrap()
    }
}

#[derive(Clone)]
struct StunWrapper {
    // Origin side of the channel
    sender: Arc<Mutex<mpsc::Sender<Vec<u8>>>>,
    // Destination side of the channel
    receiver: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    // Dest socket connection
    transport: UdpTransport,
}

impl StunWrapper {

    fn new(transport: UdpTransport) -> StunWrapper {
        let (tx, rx) = mpsc::channel();

        StunWrapper {
            sender: Arc::new(Mutex::new(tx)),
            receiver: Arc::new(Mutex::new(rx)),
            transport: transport,
        }
    }

    fn handle_non_stun(&self, payload: [u8; 1500]) {
        let raw_msg = self.sender.lock().unwrap().send(payload.to_vec());
    }
}

impl Transport for StunWrapper {

    // Receive the packet that comes on the other side side of the channel
    // and handle it
    fn recv(&self, payload: &mut [u8]) -> usize {
        let raw_msg = self.receiver.lock().unwrap().recv().unwrap();

        payload[0..raw_msg.len()].clone_from_slice(&raw_msg);

        debug!("Receiving {} from channel... {:?}", raw_msg.len(), &payload[0..raw_msg.len()]);

        raw_msg.len()
    }

    fn send(&self, payload: &[u8]) -> usize {
        self.transport.send(payload)
    }
}

impl RtcpStream {

    fn new(transport: StunWrapper) -> RtcpStream {
        let mut rtcp_stream = RtcpStream {
            transport: transport,
            tp: Arc::new(Mutex::new(0)),
            tc: 0,
            tn: 0,
            pmembers: 1,
            members: Arc::new(Mutex::new(1)),
            senders: Arc::new(Mutex::new(0)),
            // TODO(tlam): Set this to a fraction of available bw
            rtcp_bw: 40000,
            we_sent: Arc::new(Mutex::new(false)),
            // TODO(tlam): Set this to the probable size of the first RTCP
            // later constructed
            avg_rtcp_size: Arc::new(Mutex::new(100)),
            initial: true,
            members_table: Arc::new(Mutex::new(HashMap::new())),
            senders_table: Arc::new(Mutex::new(HashMap::new())),
            unauth_table: Arc::new(Mutex::new(HashMap::new())),
            tx_timer: Arc::new(Mutex::new(Timer::new())),
            packet_count: Arc::new(Mutex::new(0)),
            byte_count: Arc::new(Mutex::new(0)),
        };

        rtcp_stream.init_read_thread();
        rtcp_stream.init_write_thread();

        rtcp_stream
    }

    pub fn timer_expired(&mut self) {
        let new_t =  self.compute_next_tx_interval();

        self.tn = *self.tp.lock().unwrap() + new_t;

        self.tc = RtcpStream::get_time_now();

        debug!("tn {} and tc {}", self.tn, self.tc);

        if self.tn <= self.tc {
            // TODO(tlam): Transmit new RTCP
            self.process_rtcp_write();

            *self.tp.lock().unwrap() = self.tc;

            self.initial = false;

            let next_t = self.compute_next_tx_interval();
            debug!("Next time {}", next_t);
            self.schedule_timer(next_t);

        } else {
            //self.schedule_timer(new_t);
            let tc = self.tc;
            let tn = self.tn;
            self.schedule_timer(tn - tc);
        }

        self.pmembers = *self.members.lock().unwrap();

        self.check_members_timeout();
        self.check_senders_timeout();
    }

    pub fn schedule_timer(&mut self, t: u64) {
        let (tx, rx) = mpsc::channel();
        //self.callback = Some(Box::new(|| self.x()));
        //let arc = Arc::new(self.callback);
        //let this = Arc::new(Mutex::new(self));
        //let cloned_this = this.clone();
        { 
            // Scope here prevents this immutable reference to clash with the
            // line below, where we pass a mutable reference (#self.timer_
            // expired()) - don't forget, multiple immutable references or one
            // mutable reference are allowed in Rust. 
            let ref timer = self.tx_timer.lock().unwrap();
            timer.schedule_with_delay(Duration::milliseconds(t as i64),
                move || {
                    tx.send(1).unwrap();
                }
            );
        }

        //self.tn = RtcpStream::get_time_now() + t;

        rx.recv();
        debug!("Received the callback! miliseconds {}", t);

        self.timer_expired();
    }

    pub fn compute_next_deterministic_tx_interval(&self, is_sender: bool) -> f64 {
        let senders_ratio:f32 = (*self.senders.lock().unwrap() as f32) / (*self.members.lock().unwrap() as f32);
        let mut const_c: f32;
        let mut n: f32;

        // Step 1.

        // Senders is equal or less than 25% of the membership
        if senders_ratio <= 0.25 {
            // This is a sender
            if is_sender {
                const_c = (*self.avg_rtcp_size.lock().unwrap() as f32) / (0.25 * (self.rtcp_bw as f32));
                n = *self.senders.lock().unwrap() as f32;
            } else {
                const_c = (*self.avg_rtcp_size.lock().unwrap() as f32) / (0.75 * (self.rtcp_bw as f32));
                // Number of receivers
                n = (*self.members.lock().unwrap() as f32) - (*self.senders.lock().unwrap() as f32);
            }
        } else {
           const_c = (*self.avg_rtcp_size.lock().unwrap() as f32) / (self.rtcp_bw as f32);
           n = *self.members.lock().unwrap() as f32;
        }

        // Step 2.

        // Participant has sent an RTCP yet?
        let t_min: f32;
        if self.initial {
            t_min = 2.5;
        } else {
            t_min = 5.0;
        }

        debug!("Constant C is {} and rtcp avg size is {}", const_c, *self.avg_rtcp_size.lock().unwrap());

        // Step 3.

        let t = n * const_c * 8.0 * 2.0;
        let td = t_min.max(t);

        let td_ms = td * 1000.0;
        debug!("Deterministic time is {}", td_ms);

        td_ms as f64
    }


    // TODO(tlam): Deal with section 6.2 where an RTP profile may specify
    // different rtcp_bw for senders and receivers
    pub fn compute_next_tx_interval(&self) -> u64 {
        let td = self.compute_next_deterministic_tx_interval(*self.we_sent.lock().unwrap());

        // Step 4.
        let tmin = td * 0.5;
        let tmax = td * 1.5;
        let t:f64 = thread_rng().gen_range((tmin as f64), (tmax as f64)); 

        // Step 5.
        (t / (1.2182815)) as u64
    }

    fn get_time_now() -> u64 {
        let time_now = time::get_time();
        (time::precise_time_ns() as i64 / 1000 / 1000) as u64
    }

    /* Copied from oRTP (which in turn seems to have copied from liblinphone) */
    fn get_ntp_timestamp() -> u64 {
        let time_now = time::get_time();
        let msw: u64 = time_now.sec as u64 + 0x83AA7E80; /* 0x83AA7E80 is the number of seconds from 1900 to 1970 */
        // 4294967296.0 is 2^32
        let lsw: u64 = ((time_now.nsec as f64) * (((4294967296.0) * 0.000000001) as f64)) as u64;

        msw << 32 | lsw
    }


    fn on_receive(&mut self, rtcp_pkt: &RtcpPkt) {
        // TODO(tlam): Re-evaluate this method to see if we can fit this into
        // a common path between RTPs and RTCPs or separate ones

        let pkt_size = rtcp_pkt_get_size(&rtcp_pkt);
        {
            let mut avg_rtcp_size = self.avg_rtcp_size.lock().unwrap();
            *avg_rtcp_size = ((((1.0/16.0) as f32) * (pkt_size as f32)) + (((15.0/16.0) as f32) * ((*avg_rtcp_size) as f32))) as usize;
            debug!("on_receive RTCP average size is {}", *avg_rtcp_size);
        }

        self.received_non_bye_rtcp(rtcp_pkt.header.ssrc);
    }

    // TODO(tlam): Check the validity of the member as described in 6.3.3
    // - like receiving multiple packets from them or having a CNAME
    // associated.
    fn update_senders(&self, ssrc: u32) {
        let ref mut senders_table = self.senders_table.lock().unwrap();

        if (*senders_table).contains_key(&ssrc) {
            info!("ssrc {} already exists in senders table, updated", ssrc);
            (*senders_table).insert(ssrc, RtcpStream::get_time_now());
            return;          
        } else {
            // Assign current time.
            (*senders_table).insert(ssrc, RtcpStream::get_time_now());
            *self.senders.lock().unwrap() += 1;
        }
    }

    fn update_members(&self, ssrc: u32) {
        let ref mut members_table = self.members_table.lock().unwrap();
        if (*members_table).contains_key(&ssrc) {
            info!("ssrc {} already exists in members table, updated", ssrc);
            (*members_table).insert(ssrc, RtcpStream::get_time_now());
            return;
        } else {
            // Assign current time.
            (*members_table).insert(ssrc, RtcpStream::get_time_now());
            *self.members.lock().unwrap() += 1;
        }

        // TODO(tlam): Update avg_rtcp_size
    }

    pub fn received_rtp(&self, rtp_pkt: &RtpPkt) {
        self.update_members(rtp_pkt.header.ssrc);
        self.update_senders(rtp_pkt.header.ssrc);

        // Update jitter for this packet
        // TODO(tlam): We are placing a lock here that will lock the wholemap,
        // which is not good, since other ssrc's might want access
        let ref mut unauth_table = self.unauth_table.lock().unwrap();
        let ssrc_state = unauth_table.get_mut(&rtp_pkt.header.ssrc).unwrap();
        let time = RtcpStream::get_time_now();
        debug!("Time now is {}", time);

        //let transit = (time as u32) - rtp_pkt.header.timestamp;
        let transit = 0;

        // TODO(tlam): Is it correct this? Shifting u32 to i32?
        let mut d:i32 = (transit as i32) - (ssrc_state.transit as i32);

        debug!("Previous transit is {}", ssrc_state.transit);

        ssrc_state.transit = transit;
        if  d < 0 {
            d = -d;
        }

        let mut jitter = *ssrc_state.jitter.lock().unwrap();
        // rfc3550, 6.4.1: 0.0625 = 1.0 / 16.0
        jitter += 0.0625 * ((d as f32) - (jitter as f32));
        debug!("Current transit is {}, diff is {} and Jitter is {}", transit, d, jitter);
        *ssrc_state.jitter.lock().unwrap() = jitter;
    }

    pub fn sent_rtp(&self, rtp_pkt_size: u32) {
        *self.packet_count.lock().unwrap() += 1;
        *self.byte_count.lock().unwrap() += rtp_pkt_size;

        *self.we_sent.lock().unwrap() = true;
    }

    pub fn received_non_bye_rtcp(&mut self, ssrc: u32) {
        self.update_members(ssrc);
    }

    pub fn received_bye_rtcp(&mut self, ssrc: u32) {
        let mut members_table = self.members_table.lock().unwrap();
        if (*members_table).remove(&ssrc) != None {
            if *self.members.lock().unwrap() > 0 {
                *self.members.lock().unwrap() -= 1;
            }
        }

        let mut senders_table = self.senders_table.lock().unwrap();
        if (*senders_table).remove(&ssrc) != None {
            if *self.senders.lock().unwrap() > 0 {
                *self.senders.lock().unwrap() -= 1;
            }
        }
    
        if *self.members.lock().unwrap() < self.pmembers {
            info!("pmembers < members, <should> execute the reverse consideration algorithm");
            // TODO(tlam): Implement reverse consideration algo in 6.3.4
        }
    }

    pub fn check_members_timeout(&mut self) {
        // Calculate next td as a receiver
        let td = self.compute_next_deterministic_tx_interval(false);

        // TODO(tlam): Timeout multiplier defaults to 5, make it configureable
        let last_call = (self.tc) - (5 * (td as u64));

        // Remove members whose last RTP / RTCP packets were received at
        // before last_call
        // TODO(tlam): Revisit this, how can we remove while iterating
        /*self.members_table = self.members_table.into_iter()
                                 .filter(|&(_, v)| v >= last_call)
                                 .collect();
        */

        let members_table_clone = self.members_table.clone();
        let mut members_table = members_table_clone.lock().unwrap();
        let mut final_table = members_table.clone();

        let copy_keys = members_table.keys();
        for key in copy_keys {
            let value = members_table.get(key);
            if *(value.unwrap()) < (last_call as u64) {
                final_table.remove(key);
                if *self.members.lock().unwrap() > 0 {
                    *self.members.lock().unwrap() -= 1;
                }
            }
        }

        *self.members.lock().unwrap() = final_table.len() as u32;

        self.members_table = Arc::new(Mutex::new(final_table));
        // TODO(tlam): If any member is removed, the reverse consideration
        // algorithm (6.3.4) should be performed.
    }

    pub fn check_senders_timeout(&mut self) {

        // TODO(tlam): Find a way to measure the last two reports - is 
        // 2*(tc - tp) accurate?
        let last_call = self.tc - (2*(self.tc - *self.tp.lock().unwrap()));

        // Remove senders whose last RTP packets were received before the last

        /*
        self.senders_table = self.senders_table.into_iter()
                                 .filter(|&(_, v)| v >= last_call)
                                 .collect();
        */

        let senders_table_clone = self.senders_table.clone();
        let mut senders_table = senders_table_clone.lock().unwrap();
        let mut final_table = senders_table.clone();

        let copy_keys = senders_table.keys();
        for key in copy_keys {
            let value = senders_table.get(key);
            if *(value.unwrap()) < (last_call as u64) {
                final_table.remove(key);
                if *self.senders.lock().unwrap() > 0 {
                    *self.senders.lock().unwrap() -= 1;
                }
            }
        }

        *self.senders.lock().unwrap() = final_table.len() as u32;

        self.senders_table = Arc::new(Mutex::new(final_table));
    }

    // RTCP stream IO methods
    fn read(&self, mut rtcp_pkt: &mut RtcpPkt) -> usize {
        let mut udp_payload = [0; 1500];

        let size = self.transport.recv(&mut udp_payload);

        parse_rtcp_pkt(&udp_payload, rtcp_pkt);

        rtcp_pkt.size = size;

        debug!("Read an RTCP of size {}", size);

        size as usize
    }

    fn process_rtcp_write(&self) {
        let mut rtcp_pkt = RtcpPkt {
            header: RtcpHeader {
                version: 2, 
                padding: 0,
                rc: 0,
                // Default to false
                payload_type: 201,
                length: 46, // 1500 (size of packet including payload) / 32
                ssrc: 0123456789,
            },
            sender_info: None,
            report_blocks: vec![],
            size: 0,
        };

        if *self.we_sent.lock().unwrap() {
            rtcp_pkt.header.payload_type = 200;
            
            let ntp_timestamp = RtcpStream::get_ntp_timestamp();
            rtcp_pkt.sender_info = Some(SenderInfo {
                ntp_timestamp_msw: (ntp_timestamp >> 32) as u32,
                ntp_timestamp_lsw: (ntp_timestamp & 0xFFFFFFFF) as u32,
                // TODO(tlam): 
                rtp_timestamp: 0,
                sender_packet_count: *self.packet_count.lock().unwrap(),
                sender_byte_count: *self.byte_count.lock().unwrap(),
            });
        }

        let senders_table = (*self.senders_table.lock().unwrap()).clone();
        for (ssrc, time) in senders_table {
            let ref mut unauth_table = self.unauth_table.lock().unwrap();
            let ssrc_state = unauth_table.get(&ssrc).unwrap();

            // There's at least an RTP packet after the last RTCP was sent
            if time > *self.tp.lock().unwrap() {
                let ext_seq_number = *ssrc_state.cycles.lock().unwrap() + (*ssrc_state.max_seq.lock().unwrap() as u32);
                let expected = ext_seq_number - *ssrc_state.base_seq.lock().unwrap() + 1;  

                let received = *ssrc_state.received.lock().unwrap();
                // TODO(tlam): Check signedness
                let lost = expected - received;

                debug!("ssrc {}, extended sequence {}, expected {}, lost {} and cycles {}, max seq {}", ssrc, ext_seq_number, expected, lost, *ssrc_state.cycles.lock().unwrap(), (*ssrc_state.max_seq.lock().unwrap() as u32));

                let expected_interval = expected - *ssrc_state.expected_prior.lock().unwrap();
                *ssrc_state.expected_prior.lock().unwrap() = expected;

                let received_interval = received - *ssrc_state.received_prior.lock().unwrap();
                *ssrc_state.received_prior.lock().unwrap() = received;

                let lost_interval = expected_interval - received_interval;
                let fraction;
                if (expected_interval == 0) || (lost_interval <= 0) {
                    fraction = 0;
                } else {
                    // TODO(tlam): Check the cast to u8 here. Does little vs
                    // big endian matter?
                    fraction = ((lost_interval << 8) / expected_interval) as u8;
                }
                let jitter = *ssrc_state.jitter.lock().unwrap();  

                debug!("ssrc {}, expected_interval {}, received_internal {}, fraction {}", ssrc, expected_interval, received_interval, fraction);

                let report = ReportBlock {
                    ssrc: ssrc,
                    fraction_lost: fraction,
                    sum_nr_packets_lost: lost,
                    ext_seq_number: ext_seq_number,
                    jitter: (jitter as u32),
                    last_sr: 0,
                    delay_last_sr: 0,
                };

                rtcp_pkt.report_blocks.push(report);
                rtcp_pkt.header.rc += 1;
            }
        }

        self.write(&mut rtcp_pkt); 

        // Update avg_rtcp_size
        let pkt_size = rtcp_pkt_get_size(&rtcp_pkt);
        {
            let mut avg_rtcp_size = self.avg_rtcp_size.lock().unwrap();
            *avg_rtcp_size = ((((1.0/16.0) as f32) * (pkt_size as f32)) + (((15.0/16.0) as f32) * ((*avg_rtcp_size) as f32))) as usize;
        }
    }

    fn write(&self, rtcp_pkt: &mut RtcpPkt) -> usize {
        let udp_payload:[u8; 1500] = pkt_rtcp_to_udp_payload(rtcp_pkt);

        let size = self.transport.send(&udp_payload);

        rtcp_pkt.size = size;

        debug!("Sent an RTCP of size {}", size);

        size
    }

    fn handle_read(&mut self) {
        // Have this thread reading RTCPs
        while true {
            let mut rtcp_pkt = RtcpPkt {
                header: RtcpHeader {
                    version: 0, 
                    padding: 0,
                    rc: 0,
                    payload_type: 0,
                    length: 0,
                    ssrc: 0,
                },
                sender_info: None,
                report_blocks: vec![],
                size: 0,
            };

            if self.read(&mut rtcp_pkt) == 0 {
                warn!("Rtcp of length 0 received");
                break;
            }

            // Continue to process the received RTCP packet
            self.on_receive(&rtcp_pkt);
        }
    }

    pub fn schedule_write(&self, next_t: u64) {
        let mut self_clone = self.clone();

        thread::spawn(move ||{
            // spawn this to be done in a different thread
            self_clone.schedule_timer(next_t);
        });
    }

    pub fn init_write_thread(&self) {
        let next_t = self.compute_next_tx_interval();
        self.schedule_write(next_t);
    }

    pub fn init_read_thread(&self) {
        let mut self_clone = self.clone();

        thread::spawn(move ||{
            // spawn this to be done in a different thread
            self_clone.handle_read();
        });
    }
}

pub trait RirHandler {
    fn handle_event(&self, handlers::CallbackType);
}

pub fn fake_callback(callback_type: handlers::CallbackType) {
}

impl RtpSession {
    pub fn change_transport(&self, new_addr: SocketAddr) {
        let mut rsock = self.transport.transport.rem_socket.write().unwrap();
        *rsock = new_addr;
    }

    pub fn change_rtcp_transport(&self, new_addr: SocketAddr) {
        let mut rsock = self.rtcp_stream.transport.transport.rem_socket.write().unwrap();
        *rsock = new_addr;
    }

    pub fn connect_to(rtp_conn: UdpSocket, rtcp_conn: UdpSocket, socket_addr: SocketAddr, rtp_cb: Box<RirHandler + Send>, rtcp_cb: Box<RirHandler + Send>) -> RtpSession {
        let rtp_clone = rtp_conn.try_clone().unwrap();

        debug!("Setting up STUN for RTP {}:{}", rtp_conn.local_addr().unwrap().ip(), rtp_conn.local_addr().unwrap().port());

        // Build transport based on
        let transport = UdpTransport::new(rtp_conn, socket_addr);
        let stun_wrapper = StunWrapper::new(transport);

        let fn_pointer:Box<Fn(handlers::CallbackType) + Send> = Box::new(fake_callback);

        let mut executor = InPlaceExecutor::new().unwrap();
        let spawner = executor.handle();
        let monitor = executor.spawn_monitor(UdpServer::new(rtp_clone)
                              .start(spawner.boxed(), handlers::RtpHandler::new("T0teqPLNQQOf+5W+ls+P2p16".to_string(), stun_wrapper.sender.clone(), rtp_cb)));
        thread::spawn(move || {
            let result = executor.run_fiber(monitor).unwrap();
        });

        debug!("Setting up STUN for RTCP {}:{}", rtcp_conn.local_addr().unwrap().ip(), rtcp_conn.local_addr().unwrap().port());

        // TODO(tlam): Should we be assuming port+1 for RTCP initially?
        let socket_ip = socket_addr.ip();
        let socket_port = socket_addr.port() + 1;
        let rem_socket = SocketAddr::new(socket_ip, socket_port);

        let rtcp_clone = rtcp_conn.try_clone().unwrap();
        let rtcp_transport = UdpTransport::new(rtcp_conn, rem_socket);
        let rtcp_wrapper = StunWrapper::new(rtcp_transport);

        let mut executor = InPlaceExecutor::new().unwrap();
        let spawner = executor.handle();
        let monitor = executor.spawn_monitor(UdpServer::new(rtcp_clone)
                              .start(spawner.boxed(), handlers::RtpHandler::new("T0teqPLNQQOf+5W+ls+P2p16".to_string(), rtcp_wrapper.sender.clone(), rtcp_cb)));
        thread::spawn(move || {
            let result = executor.run_fiber(monitor).unwrap();
        });

        RtpSession {
            rtcp_stream: RtcpStream::new(rtcp_wrapper),
            transport: stun_wrapper,
            //handler: callback,
        }
    }

    pub fn read(&self, mut rtp_pkt: &mut RtpPkt) -> usize {
        // TODO(tlam): What if we need to read more than 1500 bytes?
        let mut udp_payload = [0; 1500];

        let size = self.transport.recv(&mut udp_payload);

        parse_pkt(&udp_payload[..size], rtp_pkt);

        let ssrc = rtp_pkt.header.ssrc;

        let valid: bool;
        let ref rtcp_stream = self.rtcp_stream;
        {
            let ref mut unauth_table = rtcp_stream.unauth_table.lock().unwrap();
            let ssrc_state = unauth_table.entry(ssrc).or_insert(SourceState::new(rtp_pkt.header.seq_number));
            valid = ssrc_state.update_seq(rtp_pkt.header.seq_number);
        }

        if valid {
            rtcp_stream.received_rtp(&rtp_pkt);

            return rtp_pkt.payload.len()
        } else {
            warn!("Rtp packet with seq {} dropped!", rtp_pkt.header.seq_number);
            return 0;
        }
    }

    pub fn write(&self, rtp_pkt: &RtpPkt) -> usize {
        let udp_payload:Vec<u8> = pkt_to_udp_payload(rtp_pkt);

        self.transport.send(&udp_payload);

        self.rtcp_stream.sent_rtp(rtp_pkt.payload.len() as u32);

        debug!("Writing RTP of size {}... {:?}", udp_payload.len(), &udp_payload[0..udp_payload.len()]);

        udp_payload.len()
    }
}

fn rtcp_pkt_get_size(rtcp_pkt: &RtcpPkt) -> usize {

    // rfc3550: The size includes lower-layer transport and network protocol
    // headers (e.g., UDP and IP) as explained in Section 6.2.
    // avg_rtcp_size = (1/16) * packet_size + (15/16) * avg_rtcp_size

    rtcp_pkt.size
}

pub fn parse_pkt(pkt: &[u8], rtp_pkt: &mut RtpPkt) {

    let mut version:u8 = pkt[0] & 0xC0;
    version >>= 6;
    let mut padding:u8 = pkt[0] & 0x20;
    padding >>= 5;
    let mut ext:u8 = pkt[0] & 0x10;
    ext >>= 4;
    let cc:u8 = pkt[0] & 0x0F;
    let mut marker:u8 = pkt[1] & 0x80;
    marker >>= 7; 
    let payload_type:u8 = pkt[1] & 0x7F;
    // Unsafe way of doing the [u8] to [u16] cast
    //let seq_number:u16 = mem::transmute([pkt[2], pkt[3]]);

    /*let mut buf = Cursor::new(&[pkt[2], pkt[3]]);
    let seq_number = buf.read_u32::<BigEndian>().unwrap();*/
    let seq_number = BigEndian::read_u16(&[pkt[2], pkt[3]]);

    /*let mut buf = Cursor::new(&[pkt[4], pkt[5], pkt[6], pkt[7]]);
    let timestamp = buf.read_u32::<BigEndian>().unwrap();*/
    let timestamp = BigEndian::read_u32(&[pkt[4], pkt[5], pkt[6], pkt[7]]);
    /*let mut buf = Cursor::new(&[pkt[8], pkt[9], pkt[10], pkt[11]]);
    let ssrc = buf.read_u32::<BigEndian>().unwrap();*/
    let ssrc = BigEndian::read_u32(&[pkt[8], pkt[9], pkt[10], pkt[11]]);

    let pkt = &pkt[12..];
    let mut csrc = [0u32, cc as u32];
    let mut csrc = vec![];
    {
        for i in 0..cc as usize {
            /*let mut buf = Cursor::new(&[pkt[i*4]]);
            csrc[i] = buf.read_u32::<BigEndian>().unwrap();
            */
            csrc.push(BigEndian::read_u32(&[pkt[i*4]]));
        }
    }

    // Get payload
    let payload = &pkt[((cc as usize)*4)..];
    if padding != 0 {
        let last_octet:usize = payload[payload.len() - 1] as usize;
        let (payload, _) = payload.split_at(payload.len() - last_octet);
    }

    rtp_pkt.header.version = version;
    rtp_pkt.header.padding = padding;
    rtp_pkt.header.ext = ext;
    rtp_pkt.header.cc = cc;
    rtp_pkt.header.marker = marker;
    rtp_pkt.header.payload_type = payload_type;
    rtp_pkt.header.seq_number = seq_number;
    rtp_pkt.header.timestamp = timestamp;
    rtp_pkt.header.ssrc = ssrc;
    rtp_pkt.header.csrc = vec![];
    //rtp_pkt.payload.clone_from_slice(payload);
    rtp_pkt.payload = vec![];
    for i in 0..payload.len() {
        rtp_pkt.payload.push(payload[i]);
    }

    debug!("I was able to decode the following fields - version {}, padding {}, ext {}, cc {}, marker {}, payload_type {}, seq_number {}, timestamp {}, ssrc {}, csrc {:?}, rtp_pkt.payload {:?}", rtp_pkt.header.version, rtp_pkt.header.padding, rtp_pkt.header.ext, rtp_pkt.header.cc, rtp_pkt.header.marker, rtp_pkt.header.payload_type, rtp_pkt.header.seq_number, rtp_pkt.header.timestamp, rtp_pkt.header.ssrc, rtp_pkt.header.csrc, rtp_pkt.payload);
}

pub fn pkt_to_udp_payload(pkt: &RtpPkt) -> Vec<u8> {

    // TODO(tlam): Derive the correct size
    let mut udp_payload: Vec<u8> = vec![0; 12 + pkt.payload.len()];
    udp_payload[0] = pkt.header.version << 6;
    udp_payload[0] |= pkt.header.padding << 5;
    udp_payload[0] |= pkt.header.ext << 4;
    udp_payload[0] |= pkt.header.cc;
    udp_payload[1] = pkt.header.marker << 7;
    udp_payload[1] |= pkt.header.payload_type;
    BigEndian::write_u16(&mut udp_payload[2..], pkt.header.seq_number);
    BigEndian::write_u32(&mut udp_payload[4..], pkt.header.timestamp);
    BigEndian::write_u32(&mut udp_payload[8..], pkt.header.ssrc);
    //udp_payload[4].write_u32::<BigEndian>(pkt.header.timestamp).unwrap();
    //udp_payload[8].write_u32::<BigEndian>(pkt.header.ssrc).unwrap();
    for i in 0..(pkt.header.cc as usize) {
        BigEndian::write_u32(&mut udp_payload[12 + (i*4)..], pkt.header.csrc[i]);
        //udp_payload[12+i].write_u8::<BigEndian>(pkt.header.csrc[i]).unwrap();
    }
    for i in 0..pkt.payload.len() {
        udp_payload[(12 + (pkt.header.cc as usize*4)) + i] = pkt.payload[i];
    }
    let index:usize = 12 + (pkt.header.cc as usize*4) + pkt.payload.len();
    if pkt.header.padding != 0 {
        udp_payload[index] = 0;
    }

    udp_payload
}

pub struct RtcpHeader {
    pub version: u8,
    pub padding: u8,
    pub rc: u8,
    pub payload_type: u8,
    pub length: u16,
    pub ssrc: u32,
}

#[derive(Debug)]
pub struct SenderInfo {
    pub ntp_timestamp_msw: u32,
    pub ntp_timestamp_lsw: u32,
    pub rtp_timestamp: u32,
    pub sender_packet_count: u32,
    pub sender_byte_count: u32,
}

#[derive(Debug)]
pub struct ReportBlock {
    pub ssrc: u32,
    pub fraction_lost: u8,
    pub sum_nr_packets_lost: u32,
    pub ext_seq_number: u32,
    pub jitter: u32,
    pub last_sr: u32,
    pub delay_last_sr: u32,
}

pub struct RtcpPkt {
    pub header: RtcpHeader,
    pub sender_info: Option<SenderInfo>,
    pub report_blocks: Vec<ReportBlock>,
    // Keep size of packet, including headers
    pub size: usize,
}

pub fn pkt_rtcp_to_udp_payload(pkt: &RtcpPkt) -> [u8; 1500] {
    let mut udp_payload: [u8; 1500] = [0; 1500];

    // Handle header
    udp_payload[0] = pkt.header.version << 6;
    udp_payload[0] |= pkt.header.padding << 5;
    udp_payload[0] |= pkt.header.rc;
    udp_payload[1] = pkt.header.payload_type;
    BigEndian::write_u16(&mut udp_payload[2..], pkt.header.length);
    BigEndian::write_u32(&mut udp_payload[4..], pkt.header.ssrc);

    // Index where report starts
    let mut report_index;
    if pkt.header.payload_type == 200 {
        match pkt.sender_info {
            Some(ref sender_info) => { 
                BigEndian::write_u32(&mut udp_payload[8..], sender_info.ntp_timestamp_msw);
                BigEndian::write_u32(&mut udp_payload[12..], sender_info.ntp_timestamp_lsw);
                BigEndian::write_u32(&mut udp_payload[16..], sender_info.rtp_timestamp);
                BigEndian::write_u32(&mut udp_payload[20..], sender_info.sender_packet_count);
                BigEndian::write_u32(&mut udp_payload[24..], sender_info.sender_byte_count);
                report_index = 28;
            },
            None => {
                error!("Sender doesn't have a valid `sender_info`, aborting sending packet");

            return udp_payload
            },
        }
    } else {
        report_index = 8;
    }

    // Read report blocks
    for i in 0..pkt.report_blocks.len() {
        let ref report_block = pkt.report_blocks[i];

        BigEndian::write_u32(&mut udp_payload[report_index..], report_block.ssrc);

        let mut fraction_sum:u32 = (report_block.fraction_lost as u32) << 24;
        fraction_sum |= (report_block.sum_nr_packets_lost & 0x00FFFFFF);
        BigEndian::write_u32(&mut udp_payload[report_index + 4..], fraction_sum);
        
        BigEndian::write_u32(&mut udp_payload[report_index + 8..], report_block.ext_seq_number);
        BigEndian::write_u32(&mut udp_payload[report_index + 12..], report_block.jitter);
        BigEndian::write_u32(&mut udp_payload[report_index + 16..], report_block.last_sr);
        BigEndian::write_u32(&mut udp_payload[report_index + 20..], report_block.delay_last_sr);

        // New index for next report
        report_index += report_index + 24;
    }

    udp_payload
}

pub fn parse_rtcp_pkt(pkt: &[u8], rtcp_pkt: &mut RtcpPkt) {

    let mut version:u8 = pkt[0] & 0xC0;
    version >>= 6;
    let mut padding:u8 = pkt[0] & 0x20;
    padding >>= 5;
    let mut rc:u8 = pkt[0] & 0x1F;
    let payload_type:u8 = pkt[1];

    let length = BigEndian::read_u16(&[pkt[2], pkt[3]]);

    let ssrc = BigEndian::read_u32(&[pkt[4], pkt[5], pkt[6], pkt[7]]);

    // TODO(tlam): Use enums here, don't be stupid.
    // TODO(tlam): And get rid of the double `if`, you can do better.
    let mut ntp_timestamp_msw = 0;
    let mut ntp_timestamp_lsw = 0;
    let mut rtp_timestamp = 0;
    let mut sender_pkt_count = 0;
    let mut sender_octet_count = 0;
    if payload_type == 200 {
        ntp_timestamp_msw = BigEndian::read_u32(&[pkt[8], pkt[9], pkt[10], pkt[11]]);
        ntp_timestamp_lsw = BigEndian::read_u32(&[pkt[12], pkt[13], pkt[14], pkt[15]]);
        rtp_timestamp = BigEndian::read_u32(&[pkt[16], pkt[17], pkt[18], pkt[19]]);
        sender_pkt_count = BigEndian::read_u32(&[pkt[20], pkt[21], pkt[22], pkt[23]]);
        sender_octet_count = BigEndian::read_u32(&[pkt[24], pkt[25], pkt[26], pkt[27]]);
        let pkt = &pkt[28..];
    } else {
        let pkt = &pkt[8..];
    }

    //let mut csrc = [0u32, rc as u32];
    let mut csrc = vec![];
    {
        for i in 0..rc as usize {
            let index = i*24;
            let ssrc = BigEndian::read_u32(&[pkt[index]]);
            let fraction_lost:u8 = pkt[index + 4];
            let mut sum_nr_packets_lost:u32 = BigEndian::read_u32(&[pkt[index + 4]]);
            sum_nr_packets_lost &= 0x00FFFFFF;
            let ext_seq_number = BigEndian::read_u32(&[pkt[index + 8]]);
            let jitter = BigEndian::read_u32(&[pkt[index + 12]]);
            let last_sr = BigEndian::read_u32(&[pkt[index + 16]]);
            let delay_last_sr = BigEndian::read_u32(&[pkt[index + 20]]);

            let report = ReportBlock {
                ssrc: ssrc,
                fraction_lost: fraction_lost,
                sum_nr_packets_lost: sum_nr_packets_lost,
                ext_seq_number: ext_seq_number,
                jitter: jitter,
                last_sr: last_sr,
                delay_last_sr: delay_last_sr,
            };

            debug!("Report received {:?}", report);
            csrc.push(report);
        }
    }

    rtcp_pkt.header.version = version;
    rtcp_pkt.header.padding = padding;
    rtcp_pkt.header.rc = rc;
    rtcp_pkt.header.payload_type = payload_type;
    rtcp_pkt.header.length = length;
    rtcp_pkt.header.ssrc = ssrc;
    rtcp_pkt.report_blocks = csrc;

     // TODO(tlam): Use enums here, don't be stupid.
    if payload_type == 200 {
        rtcp_pkt.sender_info = Some(SenderInfo {
            ntp_timestamp_msw: ntp_timestamp_msw,
            ntp_timestamp_lsw: ntp_timestamp_lsw,
            rtp_timestamp: rtp_timestamp,
            sender_packet_count: sender_pkt_count,
            sender_byte_count: sender_octet_count,
        });
    } else {
        rtcp_pkt.sender_info = None;
    }


    // TODO(tlam): Do we need to care about padding here? Can we just ignore?
    /*
    let payload = &pkt[12 + ((cc as usize)*4)..];
    if padding != 0 {
        let last_octet:usize = payload[payload.len() - 1] as usize;
        let (payload, _) = payload.split_at(payload.len() - last_octet);
    }
    */

    debug!("RTCP - I was able to decode the following fields - version {}, padding {}, rc {}, payload_type {}, length {}, ssrc {}, sender_info {:?}, report_blocks {:?}", rtcp_pkt.header.version, rtcp_pkt.header.padding, rtcp_pkt.header.rc, rtcp_pkt.header.payload_type, rtcp_pkt.header.length, rtcp_pkt.header.ssrc, rtcp_pkt.sender_info, rtcp_pkt.report_blocks);

}

