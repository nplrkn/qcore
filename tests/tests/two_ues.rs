use qcore_tests::{MockUeF1ap, framework::*};

#[async_std::test]
async fn two_ues() -> anyhow::Result<()> {
    let (mut du, qc, _dn, sims, logger) = init_f1ap().await?;

    // DU connects to CU
    du.perform_f1_setup(qc.ip_addr()).await?;

    let ue_1 =
        MockUeF1ap::new_with_session(nth_imsi(0, &sims), 1, &du, qc.ip_addr(), &logger).await?;
    let ue_2 =
        MockUeF1ap::new_with_session(nth_imsi(1, &sims), 2, &du, qc.ip_addr(), &logger).await?;

    // UE-to-UE routing
    pass_through_ue_to_ue_ipv4(&ue_1, &ue_2).await?;
    pass_through_ue_to_ue_ipv4(&ue_2, &ue_1).await
}
