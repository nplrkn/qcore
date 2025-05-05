use anyhow::{Result, bail};
use derive_deref::Deref;
use serde::Deserialize;
use slog::{Logger, error, info};
use std::collections::HashMap;
use std::fs;

#[derive(Deserialize, Debug)]
pub struct SimCreds {
    #[serde(with = "hex")]
    pub ki: [u8; 16],
    #[serde(with = "hex")]
    pub opc: [u8; 16],
}

#[derive(Deref)]
pub struct SimTable(HashMap<String, SimCreds>);

/// Load the SIM creds from file into memory.
pub fn load_sims_file(filename: &str, logger: &Logger) -> Result<&'static SimTable> {
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
    for (key, value) in table.into_iter() {
        let Some(imsi) = key.strip_prefix("imsi-") else {
            bail!("Key {} in {filename} does not start with 'imsi-'", key,)
        };
        info!(logger, "Loaded creds for IMSI: {imsi} from {filename}");
        new_table.insert(imsi.to_string(), value);
    }

    let b = Box::new(SimTable(new_table));
    Ok(Box::leak(b))
}
