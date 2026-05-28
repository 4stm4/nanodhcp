//! DHCP message types (option 53).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhcpMessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
}

impl DhcpMessageType {
    pub fn from_u8(v: u8) -> Option<DhcpMessageType> {
        use DhcpMessageType::*;
        Some(match v {
            1 => Discover,
            2 => Offer,
            3 => Request,
            4 => Decline,
            5 => Ack,
            6 => Nak,
            7 => Release,
            8 => Inform,
            _ => return None,
        })
    }

    pub fn to_u8(self) -> u8 {
        use DhcpMessageType::*;
        match self {
            Discover => 1,
            Offer => 2,
            Request => 3,
            Decline => 4,
            Ack => 5,
            Nak => 6,
            Release => 7,
            Inform => 8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for v in 1..=8u8 {
            let t = DhcpMessageType::from_u8(v).unwrap();
            assert_eq!(t.to_u8(), v);
        }
    }

    #[test]
    fn unknown_is_none() {
        assert!(DhcpMessageType::from_u8(0).is_none());
        assert!(DhcpMessageType::from_u8(99).is_none());
    }
}
