use anyhow::{Result, bail};
use derive_deref::{Deref, DerefMut};
use serde::Deserialize;
use slog::{Logger, error, info};
use std::collections::HashMap;
use std::fs;

#[derive(Deserialize, Debug, Clone)]
pub struct SimCreds {
    #[serde(with = "hex")]
    pub ki: [u8; 16],
    #[serde(with = "hex")]
    pub opc: [u8; 16],
}

#[derive(Clone)]
pub struct Subscriber {
    pub sim_creds: SimCreds,
    pub sqn: Sqn,
    // In future, this structure will become SubscriberAuthParams,
    // contained within a Subscriber struct which also has config.
}
pub type SubscriberAuthParams = Subscriber;

#[derive(Deref, DerefMut, Clone, Debug)]
pub struct Sqn(pub [u8; 6]);

impl Sqn {
    pub fn add(&mut self, amount: u8) {
        let mut scratch = [0u8; 8];
        scratch[2..8].clone_from_slice(&self.0);
        let mut s = u64::from_be_bytes(scratch);
        s += amount as u64;
        let scratch = s.to_be_bytes();
        self.clone_from_slice(&scratch[2..8]);
    }
    pub fn inc(&mut self) {
        self.add(1);
    }
}

#[derive(Deref, DerefMut, Clone)]
pub struct SubscriberDb(HashMap<String, Subscriber>);

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
            info!(logger, "Loaded creds for IMSI: {imsi} from {filename}");
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
