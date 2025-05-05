use crate::ies::Snssai;

impl From<xxap::Snssai> for Snssai {
    fn from(x: xxap::Snssai) -> Self {
        Snssai {
            sst: [x.0],
            sd: x.1,
        }
    }
}

impl From<Snssai> for xxap::Snssai {
    fn from(x: Snssai) -> Self {
        xxap::Snssai(x.sst[0], x.sd)
    }
}
