use std::collections::HashMap;

use qcore::SimCreds;
use qcore_tests::load_test::generate_load_test_sims;

fn main() {
    const UE_COUNT: usize = 200;
    let sims = generate_load_test_sims(UE_COUNT);

    let table: HashMap<String, SimCreds> = sims
        .0
        .into_iter()
        .map(|(k, v)| (format!("imsi-{k}"), v.sim_creds))
        .collect();

    let s = toml::to_string(&table);
    println!("{}", s.unwrap());
}
