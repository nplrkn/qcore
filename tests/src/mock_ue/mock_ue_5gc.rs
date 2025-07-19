use std::net::Ipv4Addr;

pub struct MockUe5GCData {
    pub imsi: String,
    pub guti: Option<[u8; 10]>,
    pub ipv4_addr: Ipv4Addr,
    pub dnn: Option<&'static [u8]>,
}

impl MockUe5GCData {
    pub fn new(imsi: String) -> Self {
        MockUe5GCData {
            imsi,
            guti: None,
            ipv4_addr: Ipv4Addr::UNSPECIFIED,
            dnn: None,
        }
    }
}
