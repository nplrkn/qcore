use std::fmt::{self, Display};

use crate::Guami;

impl Display for Guami {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}-{}-{}-{}",
            self.plmn_identity.0[0],
            self.plmn_identity.0[1],
            self.plmn_identity.0[2],
            self.amf_region_id.0,
            self.amf_set_id.0,
            self.amf_pointer.0
        )
    }
}
