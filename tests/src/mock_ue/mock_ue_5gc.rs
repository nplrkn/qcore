use nas::NasContext;
use qcore::SubscriberAuthParams;
use std::net::Ipv4Addr;

pub struct MockUe5GCData {
    pub imsi: String,
    pub sub_auth_params: SubscriberAuthParams,
    pub guti: Option<[u8; 10]>,
    pub ipv4_addr: Ipv4Addr,
    pub dnn: Option<&'static [u8]>,
    pub nas_context: NasContext,
}

impl MockUe5GCData {
    pub fn new(imsi: String, sub_auth_params: SubscriberAuthParams) -> Self {
        MockUe5GCData {
            imsi,
            sub_auth_params,
            guti: None,
            ipv4_addr: Ipv4Addr::UNSPECIFIED,
            dnn: None,
            nas_context: NasContext::default(),
        }
    }
}
