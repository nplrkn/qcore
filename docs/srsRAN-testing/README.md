# srsRAN demo

QCore has been tested against srsRAN on Ubuntu 22.04 running under WSL.

A big thank you to the srsRAN team for their project!

##
### Install / Build

-  Build srsRAN from source, choosing the "ZMQ Enabled installation".  Follow instructions at https://docs.srsran.com/projects/project/en/latest/user_manuals/source/installation.html#manual-installation.   

-  Build srsRAN_4G from source.  @@@ TODO

### Configuration

Using du.yml, ue.conf and sims.toml in the same directory as these instructions.

-  Copy or link `du.yml` into .../srsRAN_Project/build/apps/du
-  Copy or link `ue.conf` into .../srsRAN_4G/build/srsue/src.
-  Overwrite `qcore/sims.toml` with the sims.toml 

## Running

### Running the test

#### Terminal 1 - tcpdump

```sh
cd
sudo tcpdump -w srsran_test.pcap -i any port 38472 or port 2152 or src 10.255.0.1 or dst 10.255.0.1
```

#### Terminal 2 - QCore

```sh
cd ~/qcore
RUST_LOG=debug cargo run -- --mcc 001 --mnc 01 --local-ip 127.0.0.1
```

#### Terminal 3 - DU

```sh
cd ~/srsRAN_Project/build/apps/du
sudo ./srsdu -c du.yml
```

#### Terminal 4 - UE

```sh
cd ~/srsRAN_4G/build/srsue/src/
sudo ./srsue -c ue.conf
```

