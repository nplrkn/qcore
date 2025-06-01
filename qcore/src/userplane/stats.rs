use anyhow::{Result, bail};
use aya::maps::{MapData, PerCpuArray};
use ebpf_common::CounterIndex::{self, *};
use slog::{Logger, info, warn};
use std::fmt::Write;
use strum::VariantNames;

pub async fn dump_stats(
    logger: Logger,
    per_cpu_ebpf_counters: PerCpuArray<MapData, u64>,
) -> Result<()> {
    const FIRST_NON_RATE: usize = UlRxPkts as usize;
    const FIRST_WARN_IDX: usize = UlDropTooShort as usize;
    const SAMPLE_INTERVAL_SECS: u64 = 10;
    const RATE_APPROX_WINDOW_SECS: u64 = 30;
    const WEIGHT: f64 =
        2.0 / ((RATE_APPROX_WINDOW_SECS as f64 / SAMPLE_INTERVAL_SECS as f64) + 1.0);

    let mut rate = [0f64; FIRST_NON_RATE];

    // TODO: to cope with wrapping, we need to store a 'last' value
    // per cpu.  u64 will not wrap for many lifetimes, but if these
    // are changed to u32 at any point, that will become relevant.
    let mut last = [0u64; NumCounters as usize];

    let Ok(num_cpus) = aya::util::nr_cpus() else {
        bail!("Couldn't get num cpus")
    };

    info!(
        &logger,
        "Starting userplane stats task, num cpus {}", num_cpus
    );

    // This is to help spot if Linux is distributing our packets unevenly between CPUs.
    const CPU_HEATMAP_INTERVAL_SEC: u64 = 30;
    let mut ul_heatmap_last = vec![0u64; num_cpus];
    let mut dl_heatmap_last = vec![0u64; num_cpus];
    let mut next_cpu_heatmap = CPU_HEATMAP_INTERVAL_SEC as isize;

    loop {
        async_std::task::sleep(std::time::Duration::new(SAMPLE_INTERVAL_SECS, 0)).await;

        let mut info_needed = false;
        let mut warn_needed = false;
        let mut sum = [0u64; NumCounters as usize];

        for (stat, rate) in rate.iter_mut().enumerate().take(FIRST_NON_RATE) {
            // Take the delta of the counter and divide by the sample duration to get
            // a change per second.
            // e.g. if 5 packets arrived, that is 1pps.
            let delta = update_sum(stat, &mut sum, &mut last, &per_cpu_ebpf_counters, num_cpus)?;
            let delta_per_second = delta as f32 / SAMPLE_INTERVAL_SECS as f32;

            // Fold into the moving average to get an approximate rate over a time
            // window. e.g. "average packets per second over the last 30 seconds".
            *rate = (WEIGHT * delta_per_second as f64 + (1.0 - WEIGHT) * *rate).floor();

            // If no data is flowing, the rate will decay to 0.
            // We keep issuing info logs tracing this until it gets below 10 per second.
            if *rate >= 10.0 || delta != 0 {
                info_needed = true;
            }
        }

        for stat in FIRST_NON_RATE..FIRST_WARN_IDX {
            info_needed |=
                update_sum(stat, &mut sum, &mut last, &per_cpu_ebpf_counters, num_cpus)? != 0;
        }

        for stat in FIRST_WARN_IDX..NumCounters as usize {
            warn_needed |=
                update_sum(stat, &mut sum, &mut last, &per_cpu_ebpf_counters, num_cpus)? != 0;
        }

        if info_needed {
            let mut s = String::new();
            for (i, rate) in rate.iter().enumerate().take(FIRST_NON_RATE) {
                write!(&mut s, " {}/s={}", CounterIndex::VARIANTS[i], rate)?;
            }
            for (i, last) in last.iter().enumerate().take(FIRST_WARN_IDX) {
                write!(&mut s, " {}={}", CounterIndex::VARIANTS[i], last)?;
            }
            info!(&logger, "{}", s);
        }

        if warn_needed {
            let mut s = String::new();
            for (i, last) in last
                .iter()
                .enumerate()
                .take(NumCounters as usize)
                .skip(FIRST_WARN_IDX)
            {
                write!(&mut s, " {}={}", CounterIndex::VARIANTS[i], last)?;
            }
            warn!(&logger, "{}", s);
        }

        if info_needed {
            next_cpu_heatmap -= SAMPLE_INTERVAL_SECS as isize;
            if next_cpu_heatmap <= 0 {
                let Ok(per_cpu_ul) = per_cpu_ebpf_counters.get(&(UlRxPkts as u32), 0) else {
                    continue;
                };
                let Ok(per_cpu_dl) = per_cpu_ebpf_counters.get(&(DlRxPkts as u32), 0) else {
                    continue;
                };
                let mut ul_string = String::new();
                let mut dl_string = String::new();
                for cpu in 0..num_cpus {
                    write!(
                        &mut ul_string,
                        "{}|",
                        per_cpu_ul[cpu] - ul_heatmap_last[cpu]
                    )?;
                    write!(
                        &mut dl_string,
                        "{}|",
                        per_cpu_dl[cpu] - dl_heatmap_last[cpu]
                    )?;
                    ul_heatmap_last[cpu] = per_cpu_ul[cpu];
                    dl_heatmap_last[cpu] = per_cpu_dl[cpu];
                }
                info!(
                    &logger,
                    "UL CPU heatmap last {}s: {}", CPU_HEATMAP_INTERVAL_SEC, ul_string
                );
                info!(
                    &logger,
                    "DL CPU heatmap last {}s: {}", CPU_HEATMAP_INTERVAL_SEC, dl_string
                );

                next_cpu_heatmap = CPU_HEATMAP_INTERVAL_SEC as isize;
            }
        }
    }
}

fn update_sum(
    stat: usize,
    sum: &mut [u64],
    last: &mut [u64],
    per_cpu_ebpf_counters: &PerCpuArray<MapData, u64>,
    num_cpus: usize,
) -> Result<u64> {
    let per_cpu_values = per_cpu_ebpf_counters.get(&(stat as u32), 0)?;
    for cpu in 0..num_cpus {
        sum[stat] += per_cpu_values[cpu];
    }
    let delta = sum[stat] - last[stat];
    last[stat] = sum[stat];
    Ok(delta)
}
