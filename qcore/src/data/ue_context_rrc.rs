use pdcp::PdcpTx;

#[derive(Debug, Default)]
pub struct UeContextRrc {
    pub pdcp_tx: PdcpTx,
}
