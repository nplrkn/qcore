use qcore_tests::{MockUe, framework::*};

#[async_std::test]
async fn attach_ngap() -> anyhow::Result<()> {
    let (mut gnb, qc, dn, sims, logger) = init_ngap().await?;

    // This test carries out the attach flow - see docs/attach.md.

    // DU connects to CU
    gnb.perform_ng_setup(qc.ip_addr()).await
}
