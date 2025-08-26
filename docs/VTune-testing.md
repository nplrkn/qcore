# Perf profiling with Intel VTune

Install VTune.

```sh
sudo sysctl -w kernel.yama.ptrace_scope=0
sudo sysctl -w kernel.kptr_restrict=0
cargo test --profile bench --test load_test -- --ignored --nocapture # note the name of the test binary
sudo su
source /opt/intel/oneapi/vtune/latest/env/vars.sh
# substitue name of test binary in the below
vtune -collect hotspots -result-dir vtune`date '+%F-%H-%M-%S'` target/release/deps/load_test-311eec0112284af3
``` 

You can now import the results from the vtune... directory into the VTune GUI.

If the 'running perf script' step is very slow, see https://github.com/flamegraph-rs/flamegraph/issues/74#issuecomment-2089218416
for how to replace 'addr2line' with the gimli version.

