# Comparative load testing against Open5GS

## Results

As measured by the QCore load test:
-  Open5GS's time to execute the test message sequence: ~34ms, using around 85% CPU
-  QCore's time to execute the test message sequence: ~1ms, using around 70% CPU

Conclusion: the QCore control plane is >30x faster than Open5GS and ~40x more efficient in terms of CPU usage.

The main time in Open5GS was spent in open5gs-scpd (27%), mongod (15%), open5gs-amfd (13%), 
open5gs-udmd (8%), and open5gs-smfd (8%).

## Methodology

-  The test message sequence is a 29-message sequence of: registration, configuration update, session establishment, context release, service request, session release, deregistration.

-  The test loops repeatedly through 200 UEs running through the message sequence for each UE serially.

-  The results above were measured on a single hyperthread of a 12th Gen Intel(R) Core(TM) i7-1260P.  The method used for confining the cores to a single hyperthread is given below.

-  The times quoted above are averaged over several runs.

-  The CPU measurements are approximate and taken from `top`.  In the case of Open5GS, mongod usage was
   included in the quoted number but systemd-journal and rsyslogd were not.

-  Open5GS was installed as an Ubuntu package and not tuned in any way.


## Instructions

### Install Open5GS and confine it to a single CPU
-  Follow the instructions at https://open5gs.org/open5gs/docs/guide/01-quickstart/ to install MongoDB and Open5GS.
-  In /etc/open5gs/nrf.yaml, set mcc to 001 and mnc to 01 
-  In /etc/open5gs/amf.yaml, set mcc and mnc as above (multiple places), and set the NGAP address to 127.0.0.1. 
-  Confine Open5GS to a CPU of your choice
   - sudo vi system/multi-user.target.wants/open5gs-*.service
     -  for each udr,pcf,scp,amf,udm,smf,ausf,bsf,upf,
     -  add AllowedCPUs=<x> to the [Service] section, where x is the CPU to confine Open5GS to.
   - same for system/multi-user.target.wants/mongod.service 
   - sudo systemctl daemon-reload
   - sudo systemctl restart all of the above services
-  Run `top`, enter `f` then use the cursor keys select `P` to show the CPU that the process are running on.

### Setup SIMs
```sh
# Build QCore in release mode
cd qcore
cargo build --release

# Get Open5GS's dbctl script from github
wget https://raw.githubusercontent.com/open5gs/open5gs/refs/heads/main/misc/db/open5gs-dbctl
chmod +x open5gs-dbctl

# Generate 200 test SIMs in PLMN 00101.
./target/release/generate-load-test-sims > load_test_sims.toml

# Create a script for configuring Open5GS with these SIMs.
./target/release/provision-open5gs > provision-open5gs

# Run it - this takes a few 10s of seconds
sh provision-open5gs
```

### Run load test against Open5GS and qcore 
```sh
# Run the load test against Open5GS
./target/release/load-test

# Stop Open5GS
sudo systemctl stop open5gs-amfd

# (Separate terminal) Run QCore
cd qcore
taskset --cpu-list 7 sudo ./target/release/qcore --mcc 001 --mnc 01 --local-ip 127.0.0.1 --ran-interface-name lo --sim-cred-file load_test_sims.toml > qcore.log 2>&1

# Run the load test against QCore
./target/release/load-test
```

### Open5GS debugging if needed
Best place to start is the AMF logs:
```sh
sudo tail -f /var/log/open5gs/amf.log
```

