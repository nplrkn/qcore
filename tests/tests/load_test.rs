use std::collections::HashMap;

use qcore::{SimCreds, Sqn, Subscriber, SubscriberDb};
/// This test passes several thousand control plane messages through QCore for performance profiling purposes.
/// The call flow used is: registration, session establishment, context release, service request.
/// For 250 UEs.
use qcore_tests::{MockUeNgap, framework::*};

#[async_std::test]
async fn load_test() -> anyhow::Result<()> {
    const UE_COUNT: usize = 200;
    let mut sub_db = SubscriberDb(HashMap::new());
    for ue_id in 1..=UE_COUNT {
        let imsi = format!("001010000000{:0>3}", ue_id);
        sub_db.0.insert(
            imsi,
            Subscriber {
                sim_creds: SimCreds {
                    ki: [0u8; 16],
                    opc: [0u8; 16],
                },
                sqn: Sqn([0u8; 6]),
            },
        );
    }

    let (mut gnb, qc, _dn, sims, logger) = init_ngap_with_subdb(sub_db).await?;

    gnb.perform_ng_setup(qc.ip_addr()).await?;

    for ue_id in 1..=UE_COUNT {
        println!("UE {ue_id}");
        let mut ue = MockUeNgap::new_with_session(
            nth_imsi(ue_id - 1, &sims),
            ue_id as u32,
            &gnb,
            qc.ip_addr(),
            &logger,
        )
        .await?;
        gnb.send_ue_context_release_request(ue.gnb_ue_context())
            .await?;
        gnb.handle_ue_context_release(ue.gnb_ue_context()).await?;
        let _old_ue_context = gnb
            .reset_ue_context(ue.gnb_ue_context(), qc.ip_addr())
            .await?;
        ue.send_nas_service_request().await?;
        gnb.handle_initial_context_setup_with_session(ue.gnb_ue_context())
            .await?;
        ue.receive_nas_service_accept().await?;
        ue.handle_nas_configuration_update().await?;
    }

    Ok(())
}
