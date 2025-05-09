# srsRAN demo

In this demo, we are going to ping a public IPv4 address from a simulated UE, running through the srsRAN DU, and QCore.  Below is a complete walkthrough.

Thank you to the team at srsRAN for their project!

QCore has been tested against [srsRAN](https://www.srslte.com/5g) on Ubuntu 22.04, running under WSL (Windows Subsystem for Linux).  The specific commit of srsRAN used was 644263b5a7c7b98b892bc1120940ae8d801eaee0 for srsRAN_Project and ec29b0c1ff79cebcbe66caa6d6b90778261c42b8 for srsRAN_4G.

### Clone and build QCore

```sh
git clone https://github.com/nplrkn/qcore.git  
cd qcore
cargo build
```

### Clone and build srsRAN DU and UE

```sh
# Get ZMQ
sudo apt-get install libzmq3-dev

# Build srsRAN_PROJECT with ZMQ
# Instructions taken from https://docs.srsran.com/projects/project/en/latest/user_manuals/source/installation.html#manual-installation-build
sudo apt-get install cmake make gcc g++ pkg-config libfftw3-dev libmbedtls-dev libsctp-dev libyaml-cpp-dev libgtest-dev
git clone https://github.com/srsran/srsRAN_Project.git
cd srsRAN_Project
mkdir build
cd build
cmake ../ -DENABLE_EXPORT=ON -DENABLE_ZEROMQ=ON
make -j`nproc`

# Build srsRAN_4G with ZMQ
# From https://docs.srsran.com/projects/4g/en/latest/app_notes/source/zeromq/source/index.html
sudo apt-get install build-essential cmake libfftw3-dev libmbedtls-dev libboost-program-options-dev libconfig++-dev libsctp-dev
git clone https://github.com/srsRAN/srsRAN_4G.git
cd srsRAN_4G
mkdir build
cd build
cmake ../
make
```

### Set up routing and NAT

```sh
~/qcore/setup-routing
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo ip netns add ue1
``` 

### Copy across config files

```sh
cp ~/qcore/docs/srsRAN-testing/du.yml ~/srsRAN_Project/build/apps/du
cp ~/qcore/docs/srsRAN-testing/ue.conf ~/srsRAN_4G/build/srsue/src
```

### Running the test

#### Terminal 1 - tcpdump

```sh
cd
sudo tcpdump -w srsran_test.pcap -i any port 38472 or port 2152 or src 10.255.0.1 or dst 10.255.0.1
```

#### Terminal 2 - QCore

```sh
cd ~/qcore
RUST_LOG=debug cargo run -- --mcc 001 --mnc 01 --local-ip 127.0.0.1 --sim-cred-file docs/srsRAN-testing/srs-sim.toml
```

#### Terminal 3 - DU

```sh
cd ~/srsRAN_Project/build/apps/du
sudo ./srsdu -c du.yml
```

#### Terminal 4 - UE

```sh
cd ~/srsRAN_4G/build/srsue/src/
sudo ./srsue ue.conf
```

#### Terminal 5 - ping

```sh
sudo ip netns exec ue1 bash
# We are now running as root in netns ue1
ip route add default dev tun_srsue
ping 8.8.8.8
```

### Looking at the packet capture

Stop the test by hitting Ctrl-C in all of the terminals and view the pcap in Wireshark.  

