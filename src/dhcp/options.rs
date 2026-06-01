//! DHCP options: defensive TLV parser and a small writer.
//!
//! The parser never reads outside the buffer: a truncated length byte or an
//! option claiming more bytes than remain simply ends parsing. Unknown options
//! are kept verbatim and ignored by callers.

use std::net::Ipv4Addr;

use super::message::DhcpMessageType;

pub const OPT_PAD: u8 = 0;
pub const OPT_SUBNET_MASK: u8 = 1;
pub const OPT_ROUTER: u8 = 3;
pub const OPT_DNS: u8 = 6;
pub const OPT_HOSTNAME: u8 = 12;
pub const OPT_REQUESTED_IP: u8 = 50;
pub const OPT_LEASE_TIME: u8 = 51;
pub const OPT_MSG_TYPE: u8 = 53;
pub const OPT_SERVER_ID: u8 = 54;
pub const OPT_PARAM_REQUEST_LIST: u8 = 55;
pub const OPT_END: u8 = 255;

/// Parsed DHCP options, in the order they appeared.
#[derive(Debug)]
pub struct Options {
    items: Vec<(u8, Vec<u8>)>,
}

impl Options {
    /// Parse the options area (everything after the magic cookie). Always
    /// succeeds — malformed trailing data is dropped.
    pub fn parse(buf: &[u8]) -> Options {
        let mut items = Vec::new();
        let mut i = 0usize;
        while i < buf.len() {
            let code = buf[i];
            if code == OPT_PAD {
                i += 1;
                continue;
            }
            if code == OPT_END {
                break;
            }
            // A non-pad/non-end option needs a length byte.
            if i + 1 >= buf.len() {
                break;
            }
            let len = buf[i + 1] as usize;
            let start = i + 2;
            let end = match start.checked_add(len) {
                Some(e) => e,
                None => break,
            };
            if end > buf.len() {
                // Option length runs past the buffer: stop, do not over-read.
                break;
            }
            items.push((code, buf[start..end].to_vec()));
            i = end;
        }
        Options { items }
    }

    pub fn get(&self, code: u8) -> Option<&[u8]> {
        self.items
            .iter()
            .find(|(c, _)| *c == code)
            .map(|(_, v)| v.as_slice())
    }

    pub fn msg_type(&self) -> Option<DhcpMessageType> {
        // RFC 2132 §9.6: option 53 has length exactly 1.
        let d = self.get(OPT_MSG_TYPE)?;
        if d.len() != 1 {
            return None;
        }
        DhcpMessageType::from_u8(d[0])
    }

    pub fn requested_ip(&self) -> Option<Ipv4Addr> {
        ipv4(self.get(OPT_REQUESTED_IP))
    }

    pub fn server_id(&self) -> Option<Ipv4Addr> {
        ipv4(self.get(OPT_SERVER_ID))
    }

    /// Option 55 (Parameter Request List): the option codes the client wants,
    /// in the order given. `None` when absent or empty.
    pub fn param_request_list(&self) -> Option<&[u8]> {
        let d = self.get(OPT_PARAM_REQUEST_LIST)?;
        if d.is_empty() {
            None
        } else {
            Some(d)
        }
    }

    /// Client-provided hostname (option 12), sanitized to hostname-safe
    /// characters so it is safe to print to logs. Returns `None` if absent or
    /// empty after sanitizing.
    pub fn hostname(&self) -> Option<String> {
        let raw = self.get(OPT_HOSTNAME)?;
        let s: String = raw
            .iter()
            .map(|&b| b as char)
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
            .collect();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }
}

/// Decode a 4-byte IPv4 option value. RFC 2132 specifies length exactly 4 for
/// the address options we read (50 Requested IP, 54 Server Identifier).
fn ipv4(data: Option<&[u8]>) -> Option<Ipv4Addr> {
    let d = data?;
    if d.len() != 4 {
        return None;
    }
    Some(Ipv4Addr::new(d[0], d[1], d[2], d[3]))
}

/// Builds the options area of a reply, TLV by TLV.
pub struct OptionsWriter {
    buf: Vec<u8>,
}

impl OptionsWriter {
    pub fn new() -> OptionsWriter {
        OptionsWriter { buf: Vec::new() }
    }

    pub fn push(&mut self, code: u8, data: &[u8]) {
        // A DHCP option length is a single byte, so the payload cannot exceed
        // 255 bytes. Every value we write is small and bounded (config
        // validation caps the DNS list at 63 servers), so this never fires from
        // client input — but assert rather than let `data.len() as u8` silently
        // truncate and emit a corrupt option if a future caller overflows it.
        assert!(
            data.len() <= u8::MAX as usize,
            "DHCP option {} payload is {} bytes, exceeds 255",
            code,
            data.len()
        );
        self.buf.push(code);
        self.buf.push(data.len() as u8);
        self.buf.extend_from_slice(data);
    }

    pub fn push_u8(&mut self, code: u8, v: u8) {
        self.push(code, &[v]);
    }

    pub fn push_u32(&mut self, code: u8, v: u32) {
        self.push(code, &v.to_be_bytes());
    }

    pub fn push_ipv4(&mut self, code: u8, ip: Ipv4Addr) {
        self.push(code, &ip.octets());
    }

    pub fn push_ipv4_list(&mut self, code: u8, ips: &[Ipv4Addr]) {
        let mut data = Vec::with_capacity(ips.len() * 4);
        for ip in ips {
            data.extend_from_slice(&ip.octets());
        }
        self.push(code, &data);
    }

    /// Append the End option and return the finished bytes.
    pub fn finish(mut self) -> Vec<u8> {
        self.buf.push(OPT_END);
        self.buf
    }
}

impl Default for OptionsWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        // msg type = DISCOVER, requested ip = 1.2.3.4, end
        let buf = [OPT_MSG_TYPE, 1, 1, OPT_REQUESTED_IP, 4, 1, 2, 3, 4, OPT_END];
        let opts = Options::parse(&buf);
        assert_eq!(opts.msg_type(), Some(DhcpMessageType::Discover));
        assert_eq!(opts.requested_ip(), Some(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn pad_is_skipped() {
        let buf = [OPT_PAD, OPT_PAD, OPT_MSG_TYPE, 1, 3, OPT_END];
        let opts = Options::parse(&buf);
        assert_eq!(opts.msg_type(), Some(DhcpMessageType::Request));
    }

    #[test]
    fn unknown_option_is_ignored_but_parsing_continues() {
        let buf = [
            200,
            2,
            0xaa,
            0xbb, // unknown option
            OPT_MSG_TYPE,
            1,
            5,
            OPT_END,
        ];
        let opts = Options::parse(&buf);
        assert_eq!(opts.msg_type(), Some(DhcpMessageType::Ack));
        assert_eq!(opts.get(200), Some(&[0xaa, 0xbb][..]));
    }

    #[test]
    fn length_past_buffer_does_not_panic() {
        // Option 1 claims 10 bytes but only 2 remain.
        let buf = [OPT_SUBNET_MASK, 10, 0xff, 0xff];
        let opts = Options::parse(&buf);
        assert!(opts.get(OPT_SUBNET_MASK).is_none());
    }

    #[test]
    fn truncated_length_byte_does_not_panic() {
        let buf = [OPT_SUBNET_MASK]; // code with no length
        let opts = Options::parse(&buf);
        assert!(opts.get(OPT_SUBNET_MASK).is_none());
    }

    #[test]
    fn no_end_option_is_fine() {
        let buf = [OPT_MSG_TYPE, 1, 1];
        let opts = Options::parse(&buf);
        assert_eq!(opts.msg_type(), Some(DhcpMessageType::Discover));
    }

    #[test]
    fn short_ipv4_option_rejected() {
        let buf = [OPT_REQUESTED_IP, 2, 1, 2, OPT_END];
        let opts = Options::parse(&buf);
        assert_eq!(opts.requested_ip(), None);
    }

    #[test]
    fn overlong_ipv4_option_rejected() {
        // RFC 2132: option 50 has length exactly 4; 5 bytes must be rejected.
        let buf = [OPT_REQUESTED_IP, 5, 1, 2, 3, 4, 5, OPT_END];
        let opts = Options::parse(&buf);
        assert_eq!(opts.requested_ip(), None);
    }

    #[test]
    fn msg_type_wrong_length_rejected() {
        // RFC 2132 §9.6: option 53 has length exactly 1.
        let buf = [OPT_MSG_TYPE, 2, 1, 2, OPT_END];
        let opts = Options::parse(&buf);
        assert_eq!(opts.msg_type(), None);
    }

    #[test]
    fn writer_roundtrips_through_parser() {
        let mut w = OptionsWriter::new();
        w.push_u8(OPT_MSG_TYPE, DhcpMessageType::Offer.to_u8());
        w.push_ipv4(OPT_SERVER_ID, Ipv4Addr::new(192, 168, 10, 1));
        w.push_u32(OPT_LEASE_TIME, 86400);
        let bytes = w.finish();

        let opts = Options::parse(&bytes);
        assert_eq!(opts.msg_type(), Some(DhcpMessageType::Offer));
        assert_eq!(opts.server_id(), Some(Ipv4Addr::new(192, 168, 10, 1)));
        assert_eq!(opts.get(OPT_LEASE_TIME), Some(&86400u32.to_be_bytes()[..]));
    }

    #[test]
    fn hostname_is_sanitized() {
        let mut buf = vec![OPT_HOSTNAME, 8];
        buf.extend_from_slice(b"lap\ntop!");
        buf.push(OPT_END);
        let opts = Options::parse(&buf);
        assert_eq!(opts.hostname().as_deref(), Some("laptop"));
    }

    #[test]
    fn param_request_list_is_read() {
        let buf = [
            OPT_PARAM_REQUEST_LIST,
            3,
            OPT_SUBNET_MASK,
            OPT_ROUTER,
            OPT_DNS,
            OPT_END,
        ];
        let opts = Options::parse(&buf);
        assert_eq!(
            opts.param_request_list(),
            Some(&[OPT_SUBNET_MASK, OPT_ROUTER, OPT_DNS][..])
        );
    }

    #[test]
    fn empty_param_request_list_is_none() {
        let buf = [OPT_PARAM_REQUEST_LIST, 0, OPT_END];
        let opts = Options::parse(&buf);
        assert_eq!(opts.param_request_list(), None);
    }
}
