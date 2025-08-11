use crate::{SimCreds, Sqn};

#[derive(Clone)]
pub struct Subscriber {
    pub sim_creds: SimCreds,
    pub sqn: Sqn,
    // In future, this structure will become SubscriberAuthParams,
    // contained within a Subscriber struct which also has config.
}
pub type SubscriberAuthParams = Subscriber;
