use super::{SimCreds, Sqn, Subscriber};
use anyhow::{Result, bail};
use slog::{Logger, debug, error, info};
use std::collections::HashMap;
use std::fs;

#[derive(Clone)]
pub struct SubscriberDb(pub HashMap<String, Subscriber>);

impl SubscriberDb {
    // Returns the table and also the 'first' key.
    pub fn new_from_sim_file(filename: &str, logger: &Logger) -> Result<(Self, Option<String>)> {
        let path = std::env::current_dir()?;
        let contents = fs::read_to_string(filename).inspect_err(|e| {
            error!(
                logger,
                "Failed to load SIM file {filename} (current directory {}) with error code {e}",
                path.display()
            )
        })?;
        let table: HashMap<String, SimCreds> = toml::from_str(&contents)?;

        // Sort it so that the info logging below is in a meaningful order.
        let mut table = table.into_iter().collect::<Vec<(String, SimCreds)>>();
        table.sort_by_key(|x| x.0.clone());
        info!(logger, "SIM count           : {} ({filename})", table.len());
        let mut first_key = None;

        let mut new_table = HashMap::new();
        for (key, sim_creds) in table.into_iter() {
            let Some(imsi) = key.strip_prefix("imsi-") else {
                bail!("Key {} in {filename} does not start with 'imsi-'", key,)
            };
            debug!(logger, "Loaded creds for imsi-{imsi}");
            new_table.insert(
                imsi.to_string(),
                Subscriber {
                    sim_creds,
                    sqn: Sqn([0u8; 6]),
                },
            );

            if first_key.is_none() {
                first_key = Some(imsi.to_string());
            }
        }
        Ok((SubscriberDb(new_table), first_key))
    }
}
