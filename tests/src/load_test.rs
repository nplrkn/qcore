use crate::{MockGnb, UeBuilder};
use anyhow::Result;
use qcore::{SimCreds, Sqn, Subscriber, SubscriberDb};
use slog::{Logger, o};
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

pub async fn load_test(amf_ip: IpAddr, sims: SubscriberDb, logger: Logger) -> Result<()> {
    let gnb_ip = "127.0.0.2";
    let mut gnb = MockGnb::new(gnb_ip, logger.new(o!("gnb" => 1))).await?;
    gnb.perform_ng_setup(&amf_ip).await?;

    let ue_count = sims.0.len();
    let mut builder = UeBuilder::new(sims, amf_ip, logger);

    const RUN_DURATION_SECS: usize = 10;
    let now = std::time::Instant::now();
    let mut run_id = 0;

    loop {
        println!(
            "Run {run_id} starting after {}ms",
            now.elapsed().as_millis()
        );
        builder.reset_ue_index().await;
        for _ in 1..=ue_count {
            // Registration + session establishment = 13 messages
            let mut ue = builder.ngap_ue(&gnb).with_session().await?;

            // Context release = 3 messages.
            gnb.send_ue_context_release_request(&ue).await?;
            gnb.handle_ue_context_release(&mut ue).await?;

            let _old_ue_context = gnb.reset_ue_context(&mut ue, &amf_ip).await?;

            // Service procedure = 3 messages.
            // (The NAS service accept is piggybacked on the initial context setup.)
            ue.send_nas_service_request().await?;
            gnb.handle_initial_context_setup_with_session(&mut ue)
                .await?;
            ue.receive_nas_service_accept().await?;

            // Session release = 4 messages.
            ue.send_nas_pdu_session_release_request().await?;
            gnb.handle_pdu_session_resource_release(&mut ue).await?;
            ue.handle_nas_session_release().await?;

            // Deregistration = 4 messages.
            ue.perform_nas_deregistration().await?;
            gnb.handle_ue_context_release(&ue).await?;
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
