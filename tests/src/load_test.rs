use crate::{MockGnb, MockUeNgap, framework::nth_imsi};
use anyhow::Result;
use qcore::{SimCreds, Sqn, Subscriber, SubscriberDb};
use slog::Logger;
use std::{collections::HashMap, net::IpAddr};

pub fn generate_load_test_sims(count: usize) -> SubscriberDb {
    let mut sub_db = SubscriberDb(HashMap::new());
    for ue_id in 1..=count {
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
    sub_db
}

pub async fn load_test(amf_ip: &IpAddr, sims: &SubscriberDb, logger: &Logger) -> Result<()> {
    let gnb_ip = "127.0.0.2";
    let mut gnb = MockGnb::new(gnb_ip, logger).await?;

    let ue_count = sims.0.len();

    gnb.perform_ng_setup(amf_ip).await?;

    const RUN_DURATION_SECS: usize = 10;
    let now = std::time::Instant::now();
    let mut run_id = 0;

    loop {
        println!(
            "Run {run_id} starting after {}ms",
            now.elapsed().as_millis()
        );
        for ue_id in 1..=ue_count {
            // Registration + session establishment = 13 messages
            let mut ue = MockUeNgap::new_with_session(
                nth_imsi(ue_id - 1, sims),
                ue_id as u32,
                &gnb,
                amf_ip,
                logger,
            )
            .await?;

            // Context release = 3 messages.
            gnb.send_ue_context_release_request(ue.gnb_ue_context())
                .await?;
            gnb.handle_ue_context_release(ue.gnb_ue_context()).await?;

            let _old_ue_context = gnb.reset_ue_context(ue.gnb_ue_context(), amf_ip).await?;

            // Service procedure = 3 messages.
            // (The NAS service accept is piggybacked on the initial context setup.)
            ue.send_nas_service_request().await?;
            gnb.handle_initial_context_setup_with_session(ue.gnb_ue_context())
                .await?;
            ue.receive_nas_service_accept().await?;

            // Session release = 4 messages.
            ue.send_nas_pdu_session_release_request().await?;
            gnb.handle_pdu_session_resource_release(ue.gnb_ue_context())
                .await?;
            ue.handle_nas_session_release().await?;

            // Deregistration = 4 messages.
            ue.perform_nas_deregistration().await?;
            gnb.handle_ue_context_release(ue.gnb_ue_context()).await?;
        }
        run_id += 1;
        if now.elapsed().as_secs() > RUN_DURATION_SECS as u64 {
            let average_time_per_call_flow_ms =
                now.elapsed().as_millis() as f64 / (run_id * ue_count) as f64;
            println!(
                "Completed {run_id} runs of {ue_count} UEs in ~{RUN_DURATION_SECS}s, average time to execute single UE call flow {average_time_per_call_flow_ms}ms"
            );
            break;
        }
    }
    Ok(())
}
