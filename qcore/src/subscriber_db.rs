use super::{SimCreds, Sqn, Subscriber};
use anyhow::{Result, bail};
use slog::{Logger, error, info};
use std::collections::HashMap;
use std::fs;

#[derive(Clone)]
pub struct SubscriberDb(pub HashMap<String, Subscriber>);

impl SubscriberDb {
    pub fn new_from_sim_file(filename: &str, logger: &Logger) -> Result<Self> {
        let path = std::env::current_dir()?;
        let contents = fs::read_to_string(filename).inspect_err(|e| {
            error!(
                logger,
                "Failed to load SIM file {filename} (current directory {}) with error code {e}",
                path.display()
            )
        })?;
        let table: HashMap<String, SimCreds> = toml::from_str(&contents)?;
        let mut new_table = HashMap::new();
        for (key, sim_creds) in table.into_iter() {
            let Some(imsi) = key.strip_prefix("imsi-") else {
                bail!("Key {} in {filename} does not start with 'imsi-'", key,)
            };
            info!(logger, "Loaded creds for imsi-{imsi} from {filename}");
            new_table.insert(
                imsi.to_string(),
                Subscriber {
                    sim_creds,
                    sqn: Sqn([0u8; 6]),
                },
            );
        }
        Ok(SubscriberDb(new_table))
    }
}
