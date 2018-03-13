// Stun message structure
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |0 0|     STUN Message Type     |         Message Length        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Magic Cookie                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// |                     Transaction ID (96 bits)                  |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// Disclaimer: This STUN approach is not supposed to cover all the cases. The case it is supposed
// to cover is the following:
// - When we are receiving ICE STUN checks multiplexed on the RTP port allocated to receive media.
// Thus, consider this a semi-implementationon for this only.
use std::str;
use std::collections::HashMap;
use std::net::SocketAddr;

use byteorder::{ByteOrder, BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use stringprep;
use crc::crc32;
use md5;
use hmacsha1;

// In Network byte order
const MAGIC_COOKIE:u32 = 0x2112A442;
const DATA_OFFSET:u8 = 20;
const FINGERPRINT_XOR:u32 = 0x5354554e;

#[derive(Debug, PartialEq, Eq)]
enum MsgMethod {
    Binding,
    Unknown,
}

impl MsgMethod {
    pub fn from_raw(raw: u16) -> MsgMethod {
        match (raw & 0x0001) {
        0x0001 => return MsgMethod::Binding,
        _      => MsgMethod::Unknown,
        }
    }

    pub fn to_raw(mtd: &MsgMethod) -> u16 {
        match mtd {
        &MsgMethod::Binding => return 0x0001,
        &MsgMethod::Unknown => return 0xffff,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum MsgClass {
    Request,
    Indication,
    Success,
    Error,
    Unknown,
}

impl MsgClass {
    pub fn from_raw(raw: u16) -> MsgClass {
        match (raw & 0x0110) {
            0x0000 => return MsgClass::Request,
            0x0010 => return MsgClass::Indication,
            0x0100 => return MsgClass::Success,
            0x0110 => return MsgClass::Error,
            _      => return MsgClass::Unknown,
        }
    }

    pub fn to_raw(class: &MsgClass) -> u16 {
        match class {
            &MsgClass::Request => return 0x0000,
            &MsgClass::Indication => return 0x0010,
            &MsgClass::Success => return 0x0100,
            &MsgClass::Error => return 0x0110,
            &MsgClass::Unknown => return 0xffff,
        }
    }

}

enum Attr {
/*    XorMappedAddrAttr = 0x0020,
    Username = 0x0006,
    MessageIntegrity = 0x0008,
    Fingerprint = 0x8028,
    Priority = 0x0024,
    UseCandidate = 0x0025,
    IceControlled = 0x0029,
    IceControlling = 0x002a, */
    XorMappedAddrAttr(XorMappedAddrAttr),
    Username(Username),
    MessageIntegrity(MessageIntegrity),
    Fingerprint(Fingerprint),
    Priority(Priority),
    UseCandidate(UseCandidate),
    IceControlled(IceControlled),
    IceControlling(IceControlling),
    UnknownOptional(UnknownOptional),
    UnknownRequired(UnknownRequired),
}

trait StunAttr {
}

union Addr {
    v4: u32,
    v6: U128,
}

struct XorMappedAddrAttr {
    fmly: u8,
    port: u16,
    addr: Addr,
}

impl XorMappedAddrAttr {
    fn from_raw(rattr: RawAttr) -> Option<XorMappedAddrAttr> {
        let raw  = &rattr.attr_raw;
        let fmly:u8 = raw[1];
        let port:u16 = BigEndian::read_u16(&raw[2..4]);
        if fmly == 1 {
            return Some(XorMappedAddrAttr {
                fmly: fmly,
                port: port,
                addr:  Addr {
                    v4: BigEndian::read_u32(&raw[4..8]),
                }
            })
        } else {
            let le = ntoh(&raw[4..19]);
            let mut a:[u32;4] = [0; 4];
            a[0] = LittleEndian::read_u32(&le[0..4]);
            a[1] = LittleEndian::read_u32(&le[4..8]); 
            a[2] = LittleEndian::read_u32(&le[8..13]); 
            a[3] = LittleEndian::read_u32(&le[12..16]);

            return Some(XorMappedAddrAttr {
                fmly: fmly,
                port: port,
                addr: Addr {
                    v6: U128(a),
                },
            })
        }
    }

    fn to_raw(mapped_addr: &XorMappedAddrAttr) -> Vec<u8> {
        let mut raw_attr: Vec<u8> = vec![0; 12];

        BigEndian::write_u16(&mut raw_attr[0..], 0x0020);
        BigEndian::write_u16(&mut raw_attr[2..], 0x8);
        raw_attr[4] = 0x0;
        raw_attr[5] = mapped_addr.fmly;
        BigEndian::write_u16(&mut raw_attr[6..], mapped_addr.port ^ ((MAGIC_COOKIE >> 16) as u16));
        unsafe {
            BigEndian::write_u32(&mut raw_attr[8..], mapped_addr.addr.v4 ^ MAGIC_COOKIE);
        }

        raw_attr
    }
}

impl StunAttr for XorMappedAddrAttr {
}

/* TODO(tlam): Support SASLprep (can we use Rust's stringprep crate?) */
/* Seems so, as they have a saslprep function */
struct Username {
    username: String,
}

impl Username {
    fn from_raw(rattr: RawAttr) -> Option<Username> {
        let raw  = &rattr.attr_raw;

        let username = match str::from_utf8(raw) {
            Ok(v) => v,
            Err(e) => panic!("Invalid UTF-8 sequence: {:?} {}", raw, e),
        };

        /* Mandatory per rfc5389 */
        if username.len() >= 513 {
            return None
        }

        return Some(Username {
            username: username.to_owned(),
        })
    }

    fn to_raw(user: &Username) -> Vec<u8> {
        let attr_len;
        let padding;
        if user.username.len() % 4 == 0 {
            padding = 0;
            attr_len = user.username.len();
        } else {
            padding = (4 - (user.username.len() % 4));
            attr_len = user.username.len() + padding;
        }

        let mut raw_attr: Vec<u8> = vec![0; 4];

        BigEndian::write_u16(&mut raw_attr[0..], 0x0006);
        BigEndian::write_u16(&mut raw_attr[2..], (attr_len-padding) as u16);
        raw_attr.append(&mut user.username.to_owned().into_bytes());
        raw_attr.append(&mut vec![0;padding]);

        raw_attr
    }
}

impl StunAttr for Username {
}

struct MessageIntegrity {
    hash: [u8; 20],
    raw_up_to: Vec<u8>,
}

/// Attribute that validates STUN message by (as per rfc5389):
/// 1. Get all STUN message (including header);
/// 2. Commpute key by:
///     MD5(username ":" realm ":" SASLprep(password))
/// 3. Use 1. as input for hmac function and 2. as key.
impl MessageIntegrity {
    fn from_raw(rattr: RawAttr) -> Option<MessageIntegrity> {
        let raw_attr = &rattr.attr_raw;
        /* Per rfc5389, SHA1 is 20 bytes thus this field should so too  */
        if raw_attr.len() != 20 {
            return None
        }

        /* match_on_short_cred needs to change the length of the message in order to mimmic what
         * was done on the other side. Thus, we need to own the data here */
        let raw = rattr.precd_msg.unwrap();
        /*if !MessageIntegrity::match_on_short_cred(raw_attr, raw, passwd) {
            return None
        }*/

        let mut hash:[u8;20] = [0;20];
        for (x, y) in raw_attr.iter().zip(hash.iter_mut()) {
            *y = *x;
        }

        Some(MessageIntegrity {
            hash: hash,
            raw_up_to: raw,
        })
    }

    // Validate MessageIntegraty attribute, using the short term
    // credentials method:
    pub fn match_on_short_cred(&self, passwd: &str) -> bool {
        // 1. Get password and SASLprep(password);
        let ped = stringprep::saslprep(passwd);
        if ped.is_err() {
            return false
        }
        let ped = ped.unwrap().into_owned();
        // 2. Modify messasge len to point to MessageIntegrity's end
        let mut raw = self.raw_up_to.clone();
        let msg_len = raw.len() + 4;
        BigEndian::write_u16(&mut raw[2..4], (msg_len as u16));
        // 3. Hash 2. using 1. as key
        let mhash = hmacsha1::hmac_sha1(ped.as_bytes(), &raw);
        /* Sha computed doesn't match the expected, return error */
        if mhash != self.hash {
            return false
        }

        true
    }

    fn to_raw(raw: &mut [u8], passwd: &str) -> Vec<u8> {
        let ped = stringprep::saslprep(passwd);
        if ped.is_err() {
            return vec![0;1]
        }
        let ped = ped.unwrap().into_owned();
        // 2. Modify message len to point to MessageIntegrity's end
        let msg_len:u16 = BigEndian::read_u16(&raw[2..4]);
        BigEndian::write_u16(&mut raw[2..4], msg_len + 24);
        // 3. Hash 2. using 1. as key
        let hash = hmacsha1::hmac_sha1(ped.as_bytes(), &raw);

        let mut raw_attr: Vec<u8> = vec![0; 4];

        BigEndian::write_u16(&mut raw_attr[0..], 0x0008);
        BigEndian::write_u16(&mut raw_attr[2..], 0x14);
        raw_attr.extend_from_slice(&hash);

        raw_attr
    }
}

impl StunAttr for MessageIntegrity {
}

struct Fingerprint {
    fingerprint: u32,
    raw_up_to: Vec<u8>,
}

impl Fingerprint {
    fn from_raw(rattr: RawAttr) -> Option<Fingerprint> {
        let raw = &rattr.attr_raw;
        /* Find value in attribute */
        let exp = BigEndian::read_u32(&raw[0..4]);

        return Some(Fingerprint {
            fingerprint: exp,
            raw_up_to: rattr.precd_msg.unwrap(),
        })
    }

    pub fn is_valid(&self) -> bool {
        let raw = &self.raw_up_to;
        let crc = crc32::checksum_ieee(raw) ^ FINGERPRINT_XOR;
        if crc != self.fingerprint {
            return false
        }

        true
    }

    fn to_raw(raw: &mut [u8]) -> Vec<u8> {
        let msg_len = BigEndian::read_u16(&raw[2..4]);
        BigEndian::write_u16(&mut raw[2..4], msg_len + 8);

        let crc = crc32::checksum_ieee(&raw) ^ FINGERPRINT_XOR;

        let mut raw_attr: Vec<u8> = vec![0; 8];

        BigEndian::write_u16(&mut raw_attr[0..], 0x8028);
        BigEndian::write_u16(&mut raw_attr[2..], 0x4);
        BigEndian::write_u32(&mut raw_attr[4..], crc);

        raw_attr
    }
}

impl StunAttr for Fingerprint {
}

struct Priority {
    priority: u32,
}

impl Priority {
    fn from_raw(rattr: RawAttr) -> Option<Priority> {
        let raw = &rattr.attr_raw;
        /* Find value in attribute */
        let prio = BigEndian::read_u32(&raw[0..4]);

        return Some(Priority {
            priority: prio,
        })
    }
}

impl StunAttr for Priority {
}

/* Flag attribute */
struct UseCandidate;

impl UseCandidate {
    fn from_raw(rattr: RawAttr) -> Option<UseCandidate> {
        return Some(UseCandidate {
        })
    }
}

impl StunAttr for UseCandidate {
}

struct IceControlled {
    tie_br: u64,
}

impl IceControlled {
    fn from_raw(rattr: RawAttr) -> Option<IceControlled> {
        let raw = &rattr.attr_raw;
        /* Find value in attribute */
        let tie_br = BigEndian::read_u64(&raw[0..8]);

        return Some(IceControlled {
            tie_br: tie_br,
        })
    }
}

impl StunAttr for IceControlled {
}

struct IceControlling {
    tie_br: u64,
}

impl IceControlling {
    fn from_raw(rattr: RawAttr) -> Option<IceControlling> {
        let raw = &rattr.attr_raw;
        /* Find value in attribute */
        let tie_br = BigEndian::read_u64(&raw[0..8]);

        return Some(IceControlling {
            tie_br: tie_br,
        })
    }
}

impl StunAttr for IceControlling {
}

struct UnknownOptional;

impl UnknownOptional {
    fn from_raw(rattr: RawAttr) -> Option<UnknownOptional> {
        return Some(UnknownOptional)
    }
}

impl StunAttr for UnknownOptional {
}

struct UnknownRequired;

impl UnknownRequired {
    fn from_raw(rattr: RawAttr) -> Option<UnknownRequired> {
        return Some(UnknownRequired)
    }
}

impl StunAttr for UnknownRequired {
}


/*impl StunAttr {
    /*pub fn from_raw(typ: u16, raw: &[u8]) -> StunAttr {
    }*/

    fn is_mandatory(typ: u16) -> bool {
        if typ >= 0x8000 && typ <= 0xFFFF {
            return false
        }

        /* Mandatory to understand and parse, non-optional */
        return true
    }
}*/

pub struct StunPkt {
    msg_mt: MsgMethod,
    msg_cl: MsgClass,
    msg_len: u16,
    trans_id: U96,
    attrs: HashMap<u16, /*Box<StunAttr>*/Attr>,
}

fn ntoh(raw: &[u8]) -> Vec<u8> {
    let mut le: Vec<u8> = vec![];
    for i in 0..raw.len() {
        le.push(raw[raw.len() - i - 1]);
    }

    return le
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct U96 ([u32;3]);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct U128 ([u32;4]);

struct RawAttr {
    attr_raw: Vec<u8>,
    precd_msg: Option<Vec<u8>>,
    passwd: Option<String>,
}

struct AttrErr {
}

#[derive(Clone)]
pub struct Stun {
    passwd: String,
    lsock: SocketAddr,
}

impl Stun {
    pub fn new(passwd: &str, lsock: SocketAddr) -> Stun {
        Stun {
            passwd: passwd.to_owned(),
            lsock: lsock,
        }
    }

    fn error(&self, packet: &StunPkt) {
    }

    fn success(&self, packet: &StunPkt) -> StunPkt {
        let mut sucss_pkt = StunPkt {
            msg_mt: MsgMethod::Binding,
            msg_cl: MsgClass::Success,
            msg_len: 0,
            trans_id: packet.trans_id,
            attrs: HashMap::new(),
        };

        let username = packet.attrs.get(&0x0006);
        let mut resp_user;
        if let &Attr::Username( ref x ) =  username.unwrap() {
            resp_user = Username {
                username: x.username.to_owned(),
            };

            sucss_pkt.attrs.insert(0x0006, Attr::Username(resp_user));
        }
        let addr;
        let fmly;
        match self.lsock {
            SocketAddr::V4(ipv4) => {
                fmly = 1;
                addr = Addr {
                    v4: BigEndian::read_u32(&ipv4.ip().octets()),
                };
            },
            SocketAddr::V6(ipv6) => {
                fmly = 2;
                addr = Addr {
                    v6: U128([0; 4]),
                };

            },
        }

        let mapped_addr = XorMappedAddrAttr {
                fmly: fmly,
                port: self.lsock.port(),
                addr: addr,
        };
        sucss_pkt.attrs.insert(0x0020, Attr::XorMappedAddrAttr(mapped_addr));

        let msg_itgt = packet.attrs.get(&0x0008);
        let mut resp_msg_itgt;
        if let &Attr::MessageIntegrity( ref x ) =  msg_itgt.unwrap() {
            resp_msg_itgt = MessageIntegrity {
                hash: [0; 20],
                raw_up_to: Vec::new(),
            };

            sucss_pkt.attrs.insert(0x0008, Attr::MessageIntegrity(resp_msg_itgt));
        }

        let fingerprint = packet.attrs.get(&0x8028);
        let mut resp_fingerprint;
        if let &Attr::Fingerprint( ref x ) =  fingerprint.unwrap() {
            resp_fingerprint = Fingerprint {
                fingerprint: 0,
                raw_up_to: Vec::new(),
            };

            sucss_pkt.attrs.insert(0x8028, Attr::Fingerprint(resp_fingerprint));
        }

        sucss_pkt
    }

    fn to_raw(&self, pkt: &StunPkt) -> Vec<u8> {
        let mut raw_pkt:Vec<u8> = vec![0; 20];

        let msg_mt = MsgMethod::to_raw(&pkt.msg_mt);
        let msg_cl = MsgClass::to_raw(&pkt.msg_cl);
        BigEndian::write_u16(&mut raw_pkt[0..], msg_mt | msg_cl);
        BigEndian::write_u16(&mut raw_pkt[2..], 0);
        BigEndian::write_u32(&mut raw_pkt[4..], MAGIC_COOKIE);
        BigEndian::write_u32(&mut raw_pkt[8..], pkt.trans_id.0[2]);
        BigEndian::write_u32(&mut raw_pkt[12..], pkt.trans_id.0[1]);
        BigEndian::write_u32(&mut raw_pkt[16..], pkt.trans_id.0[0]);

        let username = pkt.attrs.get(&0x0006);
        if let &Attr::Username( ref x ) = username.unwrap() {
            let mut rattr = Username::to_raw(x);
            let msg_len:u16 = BigEndian::read_u16(&raw_pkt[2..4]);
            BigEndian::write_u16(&mut raw_pkt[2..4], msg_len + (rattr.len() as u16));
            raw_pkt.append(&mut rattr);
        }

        let mapped_addr = pkt.attrs.get(&0x0020);
        if let &Attr::XorMappedAddrAttr( ref x ) = mapped_addr.unwrap() {
            let mut rattr = XorMappedAddrAttr::to_raw(x);
            let msg_len:u16 = BigEndian::read_u16(&raw_pkt[2..4]);
            BigEndian::write_u16(&mut raw_pkt[2..4], msg_len + (rattr.len() as u16));
            raw_pkt.append(&mut rattr);
        }

        let msg_itgt = pkt.attrs.get(&0x0008);
        if let &Attr::MessageIntegrity( ref x ) = msg_itgt.unwrap() {
            let mut rattr = MessageIntegrity::to_raw(&mut raw_pkt, &self.passwd);
            raw_pkt.append(&mut rattr);
        }

        let fingerprint = pkt.attrs.get(&0x8028);
        if let &Attr::Fingerprint( ref x ) = fingerprint.unwrap() {
            let mut rattr = Fingerprint::to_raw(&mut raw_pkt);

            raw_pkt.append(&mut rattr);
        }

        let new_len = (raw_pkt.len()-20) as u16;
        BigEndian::write_u16(&mut raw_pkt[2..4], new_len);

        raw_pkt
    }

    fn validate(&self, packet: &StunPkt) -> Option<u8> {
        /* 1. validate the FINGERPRINT, iff in use */
        let fingerprint = packet.attrs.get(&0x8028);
        if let &Attr::Fingerprint( ref x ) = fingerprint.unwrap() {
            if !x.is_valid() {
                return Some(0)/*Err("Fingerprints mismatch")*/
            }
        }

        /* 2. Perform authentication of the message, using short-credentials
        in MESSAGE-INTEGRITY */
        let msg_itgt = packet.attrs.get(&0x0008);
        if let &Attr::MessageIntegrity( ref x ) =  msg_itgt.unwrap() {
            if !x.match_on_short_cred(&self.passwd) {
                return Some(0)/*Err("Message-Integritty check mismatch")*/
            }
        }

        /* Unknown required attributes should be saved to be sent with Error */
        let mut unk_attrs: Vec<&u16> = Vec::new();
        for (k, v) in packet.attrs.iter() {
            if k >= &0x0000 && k <= &0x7FFF {
                if let &Attr::UnknownRequired( _ ) = v {
                    unk_attrs.push(k);
                }
            }
        }
        /*let unk_attrs = packet.attrs.into_iter().filter_map(|(key, value)| {
            if key >= 0x0000 && key <= 0x7FFF {
                value.to_owned()
            }
        }).collect();*/

        Some(1)
    }

    fn parse_attr(&self, raw: &[u8], attr_idx: usize, attr_len: usize,
                  attr_typ: u16) -> Result</*Box<StunAttr>*/Attr, AttrErr> {
        let mut rattr = RawAttr {
            attr_raw: raw[attr_idx..attr_idx+attr_len].to_owned(),
            precd_msg: None,
            passwd: None,
        };

        /*
        let attr:Box<StunAttr> = match (attr_typ & 0xFFFF) {
            0x0006 => {
                Box::new(Username::from_raw(rattr).unwrap())
            },
            0x0008 => {
                rattr.precd_msg = Some(raw[0..attr_idx-4].to_owned());
                //rattr.passwd = Some(self.passwd.to_owned());
                Box::new(MessageIntegrity::from_raw(rattr).unwrap())
            },
            0x0020 => {
                Box::new(XorMappedAddrAttr::from_raw(rattr).unwrap())
            },
            0x0024 => {
                Box::new(Priority::from_raw(rattr).unwrap())
            },
            0x0025 => {
                Box::new(UseCandidate::from_raw(rattr).unwrap())
            },
            0x0029 => {
                Box::new(IceControlled::from_raw(rattr).unwrap())
            },
            0x002a => {
                Box::new(IceControlling::from_raw(rattr).unwrap())
            },
            0x8028 => {
                rattr.precd_msg = Some(raw[0..attr_idx-4].to_owned());

                Box::new(Fingerprint::from_raw(rattr).unwrap())
            },
            _ => return Err(AttrErr{})
        };
        */

        let attr = match (attr_typ & 0xFFFF) {
            0x0006 => {
                Attr::Username(Username::from_raw(rattr).unwrap())
            },
            0x0008 => {
                rattr.precd_msg = Some(raw[0..attr_idx-4].to_owned());
                //rattr.passwd = Some(self.passwd.to_owned());
                Attr::MessageIntegrity(MessageIntegrity::from_raw(rattr).unwrap())
            },
            0x0020 => {
                Attr::XorMappedAddrAttr(XorMappedAddrAttr::from_raw(rattr).unwrap())
            },
            0x0024 => {
                Attr::Priority(Priority::from_raw(rattr).unwrap())
            },
            0x0025 => {
                Attr::UseCandidate(UseCandidate::from_raw(rattr).unwrap())
            },
            0x0029 => {
                Attr::IceControlled(IceControlled::from_raw(rattr).unwrap())
            },
            0x002a => {
                Attr::IceControlling(IceControlling::from_raw(rattr).unwrap())
            },
            0x8028 => {
                rattr.precd_msg = Some(raw[0..attr_idx-4].to_owned());

                Attr::Fingerprint(Fingerprint::from_raw(rattr).unwrap())
            },
            v => {
                if v >= 0x0000 && v <= 0x7FFF {
                    Attr::UnknownRequired(UnknownRequired::from_raw(rattr).unwrap())
                } else {
                    Attr::UnknownOptional(UnknownOptional::from_raw(rattr).unwrap())
                }
            }
        };

        return Ok(attr)
    }

    /// Parse the attributes present in 'raw', injecting them into the packet
    fn parse_attrs(&self, raw: &[u8], len: usize, packet: &mut StunPkt) {
        let rattrs: &[u8] = &raw[(DATA_OFFSET as usize)..];
        let mut i = 0;
        while i < len {
            let attr_typ:u16 = BigEndian::read_u16(&rattrs[i..i+2]);
            let mut attr_len:u16 = BigEndian::read_u16(&rattrs[i+2..i+4]);
            println!("Attr type {} len {} msg_len {}", attr_typ, attr_len, len);
            //let attr_val = raw[(DATA_OFFSET as usize)+i+4..(DATA_OFFSET as usize)+i+1+(attr_len as usize)].to_vec();
            let attr = self.parse_attr(raw, (DATA_OFFSET as usize)+i+4, attr_len as usize, attr_typ);
            // TODO(tlam): Deal with error
            let attr = match attr {
                Ok(val)  => Some(val),
                Err(err) => None,
            };

            if (attr.is_some()) {
                packet.attrs.insert(attr_typ, attr.unwrap());
            }

            /* attr_val might not be aligned */
            if attr_len%4 != 0 {
                println!("Added {} of padding", (4-attr_len%4));
                attr_len = attr_len + (4-attr_len%4);
            }
            i += (attr_len as usize) + 4;
            println!("Next i {}", i);
        }
    }

    /// Parse the 'raw' payload into a StunPkt
    pub fn parse_stun(&self, raw: &[u8]) -> Option<StunPkt> {
        let zeros:u8 = raw[0] & 0xC0;
        // If not zero, then this can't be a STUN message
        if zeros != 0 {
            return None
        }

        let msg_typ:u16 = BigEndian::read_u16(&raw[0..2]) & 0x3FFF;
        let msg_mt = MsgMethod::from_raw(msg_typ);
        let msg_cl = MsgClass::from_raw(msg_typ);
        let msg_len:u16 = BigEndian::read_u16(&raw[2..4]);
        let magic:u32 = BigEndian::read_u32(&raw[4..8]);
        /* Confirm this is a STUN message */
        if (magic != MAGIC_COOKIE) {
            return None
        }

        //TODO(tlam): Check the message length is sensible
        
        let le = ntoh(&raw[8..20]);
        let mut a:[u32;3] = [0; 3];
        a[0] = LittleEndian::read_u32(&le[0..4]);
        a[1] = LittleEndian::read_u32(&le[4..8]); 
        a[2] = LittleEndian::read_u32(&le[8..12]);
        let trans_id:U96 = U96(a);

        /* Fill packet with parsed data */

        let mut pkt = StunPkt {
            msg_mt: msg_mt,
            msg_cl: msg_cl,
            msg_len: msg_len,
            trans_id: trans_id,
            attrs: HashMap::new(),
        };

        /* TODO(tlam): Verify Msg class and emthod are not "unknown" */
        /*
        match msg_mt {
            /* Message method not supported, returning error */
            MsgMethod::Unknown => return,
            // TODO(tlam): Supportonly what's strictly needed for the connectivity checks
            _                  => pkt.msg_mt = msg_mt,
        };
        match msg_cl {
            /* Message method not supported, returning error */
            MsgClass::Unknown => return,
            // TODO(tlam): Supportonly what's strictly needed for the connectivity checks
            _                 => pkt.msg_cl = msg_cl,
        };
        */

        /* Header is always 20 bytes, rest of packet are attributes */
        self.parse_attrs(&raw, msg_len as usize, &mut pkt);

        Some(pkt)
    }

    pub fn process_stun(&self, raw: &[u8]) -> Option<Vec<u8>> {
        let pkt = self.parse_stun(raw);
        if pkt.is_none() {
            return None
        }

        let pkt = pkt.unwrap();
        /* TODO Validate parsed packet based on rfc5389, section 7.3 */
        let is_valid = self.validate(&pkt);

        /* Based on the success or error, generate the response */
        match is_valid {
            Some(x) => {
                /* Generate sucessfull response */
                let succ_pkt = self.success(&pkt);

                Some(self.to_raw(&succ_pkt))
            },
            None => { return None }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const PAYLOAD1:[u8;108] = [0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xa4, 0x42, 0x43, 0x75, 0x48, 0x31, 0x56, 0x41, 0x58, 0x66, 0x4f, 0x72, 0x46, 0x58, 0x00, 0x06, 0x00, 0x15, 0x4f, 0x79, 0x65, 0x66, 0x37, 0x75, 0x76, 0x42,
0x6c, 0x77, 0x61, 0x66, 0x49, 0x33, 0x68, 0x54, 0x3a, 0x55, 0x53, 0x31, 0x46, 0x00, 0x00, 0x00,
0xc0, 0x57, 0x00, 0x04, 0x00, 0x00, 0x00, 0x32, 0x80, 0x2a, 0x00, 0x08, 0xa7, 0xc6, 0x5f, 0x79,
0x29, 0x8b, 0x9e, 0x91, 0x00, 0x24, 0x00, 0x04, 0x6e, 0x00, 0x1e, 0xff, 0x00, 0x08, 0x00, 0x14,
0x72, 0xfc, 0xac, 0xae, 0x31, 0xe4, 0x57, 0x89, 0x42, 0xcb, 0x1d, 0x93, 0x51, 0xb6, 0xfe, 0x3b,
0xd0, 0xf7, 0x21, 0xe5, 0x80, 0x28, 0x00, 0x04, 0x78, 0xa0, 0xc9, 0xc8
];

    const PAYLOAD2:[u8;108] = [0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xa4, 0x42, 0x53, 0x36, 0x43, 0x55, 0x39, 0x34, 0x33, 0x49, 0x6e, 0x4e, 0x69, 0x39, 0x00, 0x06, 0x00, 0x15, 0x4f, 0x79, 0x65, 0x66, 0x37, 0x75, 0x76, 0x42, 0x6c, 0x77, 0x61, 0x66, 0x49, 0x33, 0x68, 0x54, 0x3a, 0x55, 0x53, 0x31, 0x46, 0x00, 0x00, 0x00, 0xc0, 0x57, 0x00, 0x04, 0x00, 0x00, 0x00, 0x32, 0x80, 0x2a, 0x00, 0x08, 0xa7, 0xc6, 0x5f, 0x79, 0x29, 0x8b, 0x9e, 0x91, 0x00, 0x24, 0x00, 0x04, 0x6e, 0x00, 0x1e, 0xfe, 0x00, 0x08, 0x00, 0x14, 0xb5, 0x46, 0x7f, 0x1c, 0xfd, 0xa8, 0xca, 0x51, 0x88, 0x9c, 0xf0, 0x8c, 0x18, 0x01, 0xec, 0x34, 0xab, 0x68, 0x6b, 0x5f, 0x80, 0x28, 0x00, 0x04, 0x3d, 0xdb, 0x55, 0xb5];

    #[test]
    fn parse_sample_request() {
        let lsock = "10.0.0.1:6000".parse()
                    .expect("Unable to parse socket address");
        let stun = Stun::new("T0teqPLNQQOf+5W+ls+P2p16", lsock);

        let pkt = stun.parse_stun(&PAYLOAD1);

        assert!(pkt.is_some());

        let pkt = pkt.unwrap();

        println!("{:?}", pkt.msg_mt);
        println!("{:?}", pkt.msg_cl);
        println!("{:?}", pkt.msg_len);
        println!("{:?}", pkt.trans_id);
        println!("{:?}", pkt.attrs.len());
    }

    #[test]
    fn to_raw() {
        let lsock = "10.0.0.1:6000".parse()
                    .expect("Unable to parse socket address");
        let stun = Stun::new("T0teqPLNQQOf+5W+ls+P2p16", lsock);

        /* Compose "real" STUN message to then be parsed to raw payload */

        let mut stun_pkt = StunPkt {
            msg_mt: MsgMethod::Binding,
            msg_cl: MsgClass::Success,
            msg_len: 0,
            trans_id: U96([0; 3]),
            attrs: HashMap::new(),
        };

        /* Insert attributes manually, as to simulate when success() method in
         * Stun inserts the attributes expected for a successfull response */

        let user = Username {
            username: "test_user".to_owned(),
        };
        stun_pkt.attrs.insert(0x0006, Attr::Username(user));

        let mapped_addr = XorMappedAddrAttr {
                fmly: 1, /* v4 */
                port: 6000, /* 6000 */
                addr: Addr {
                    v4: 167772161 /* 10.0.0.1 */
                },
        };
        stun_pkt.attrs.insert(0x0020, Attr::XorMappedAddrAttr(mapped_addr));

        let msg_itgt = MessageIntegrity {
            hash: [0; 20],
            raw_up_to: Vec::new(),
        };
        stun_pkt.attrs.insert(0x0008, Attr::MessageIntegrity(msg_itgt));

        let fingerprint = Fingerprint {
            fingerprint: 0,
            raw_up_to: Vec::new(),
        };
        stun_pkt.attrs.insert(0x8028, Attr::Fingerprint(fingerprint));

        let payload = stun.to_raw(&stun_pkt);
        println!("Payload: {:?}", payload);

        /* Parse STUN message from raw and check if parameters are correct */

        let parsed_pkt = stun.parse_stun(&payload);

        assert!(parsed_pkt.is_some());

        let parsed_pkt = parsed_pkt.unwrap();

        assert!(stun_pkt.msg_mt == parsed_pkt.msg_mt);
        assert!(stun_pkt.msg_cl == parsed_pkt.msg_cl);
        assert!(parsed_pkt.msg_len == 60);
        assert!(stun_pkt.trans_id == parsed_pkt.trans_id);
        assert!(parsed_pkt.attrs.len() == 4);
    }
}
