<h1 align="center" style="border-bottom: none">
 <img src="docs/images/monolith.jpg" alt="drawing" width="200"/><br>QCore
</h1> 

*** This project is on pause.  Please contact me on LinkedIn if you'd like to discuss. ***

QCore is a free, ultra-compact private 5G Core, written in Rust, designed to minimise compute and power cost.  

It is simple to use, and significantly outperforms other single-node 5G cores thanks to its unusual monolithic architecture which reduces internal processing overheads.  

Using a tiny 32MB executable, it can handle 30,000 control plane messages per second on a single CPU core ([details](docs/Open5GS-comparative-load-testing.md)).  The userplane is implemented using eBPF for gigabit/s throughput.

It has been tested and works well with several Android phones (Samsung, OnePlus and Oppo) but remains at an early stage of maturity.  

Please contact me via a GitHub issue or on LinkedIn if you are interested in using this project.

## Architecture overview

The three external interfaces of QCore are:
-  the N2 (NG-C) SCTP interface with the gNodeB
-  the N3 (NG-U) GTP interface with the gNodeB
-  the N6 IP interface that connects UEs to the outside world.

Whereas most 5G cores consist of many different services, QCore is a single Linux executable.  It is designed as a monolith, without the standard network function decomposition of a 5G Core.  It has no internal protocol interfaces (no SBI), and a single UE context.  

The motivation for the monolithic approach is to minimize control plane processing cost.  QCore avoids a lot of the usual network hops, context switches, database accesses and (de)serialization.  As well as performance, its minimalist design also has major benefits in the areas of ease of orchestration, security, and simplicity / speed of development. 


## Notable features

-  **DHCP UE address management**.  QCore sends DHCP requests on behalf of UEs.  This means each UE has an address on the LAN, without any local NAT.  DHCP address reservations can be used to give a UE a static IP.  (For cases where DHCP is not available or you don't want UEs on your LAN, QCore can also manage a /24 UE address space, with Linux NAT configured if required.)

-  **F1 mode**.  QCore can take on the role of a gNB-CU in addition to the 5G Core.  The idea is to allow an organization with an existing gNB-DU appliance to extend their solution to offer a complete private 5G in a box by running QCore on the same node.  When running in F1 mode, QCore exposes the F1-C and F1-U interfaces, instead of N2 and N3.

-  **Ethernet PDU sessions**.  You can configure QCore with a pool of Linux veths, and it will allocate a veth to any 5G UE that requests an Ethernet PDU session.


## Quickstart

The quickest way to see QCore in action is to [run its mainline test](#run-the-mainline-test) and look at the packet capture.

You might also want to try the [srsRAN demo](./docs/srsRAN-testing/README.md).

### Run the mainline test

#### Set up environment
Before you start, install Rust and read the [section below on the routing setup](#Interface-and-routing-setup).

```sh
# Install build dependencies
cargo install bpf-linker
rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu

# Configure QCore routing + ethernet setup 
sudo apt install iptables
sudo ./setup-routing
```

#### Packet capture
```sh
sudo tcpdump -w qcore.pcap -i any sctp or port 2152 or host 10.255.0.2
```

#### Run attach test
In a separate terminal from the packet capture, in the `qcore` directory.
```sh
RUST_LOG=info cargo test --test ngap_attach -- --nocapture
```

Once the test has finished, hit Ctrl-C to exit tcpdump, then open `qcore.pcap` in Wireshark.  In Wireshark, select Edit--Preferences--Protocols--NAS-5GS--"Try to detect and decode 5G-EA0 ciphered messages".


## Configuring and running QCore

### Linux Permissions

QCore installs various eBPF programs on startup and needs the relevant Linux permissions to do so.  QCore routing and ethernet setup also require elevated permissions. The easiest way to achieve this is to run it as root.


### sims.toml

QCore reads SIM credentials from a file.  By default it uses `sims.toml` in the current working directory - see the [sample file](./sims.toml) in the root of this project.  

Pass `--sim-cred-file` to read from a different file location.


### Interface and routing setup

QCore needs various Linux interfaces to be set up in advance for it to use.  

The [`setup-routing`](./setup-routing) script is the reference setup.  You should review this script and may need to adapt it for your purposes.  

If your LAN interface is not called `eth0`, you must specify the relevant device name, for example:
```sh
./setup-routing enp113s0
```

In addition to the comments in [`setup-routing`](./setup-routing), QCore interface use is documented in more depth in the [eBPF program design](<./docs/designs/ebpf programs.md>).


### Command-line configuration

If you run QCore without any arguments, it will read the SIM file from the current directory, derive its MCC / MNC 
from the SIM file, communicate with the RAN over eth0, and perform DHCP UE address allocation over eth0. 

Run with `--help` to see the full list of command line options.

Some common uses for command line options are as follows:

-  If you want QCore to talk to the RAN using a loopback address, pass `local-ip`, for example: `qcore --local-ip 127.0.0.1`.

-  To disable DHCP, pass `--no-dhcp` and potentially `--ue-subnet`. 

-  To enable userplane stat logging, pass `--userplane-stats`.

-  To enable debug logging, set environment variable `RUST_LOG=debug`.


### Ethernet PDU session setup

QCore supports Ethernet PDU sessions.  To enable this support, you must create Linux devices named "veth_ue_1_a", 
"veth_ue_2_a".. etc..  The [`setup-ethernet` script](./setup-ethernet) shows how to do this.

Currently, all Ethernet devices are expected to connect to the same switch / Linux bridge.  In future, QCore will support Ethernet device selection based on DNN.

QCore detects these devices on startup and attaches eBPF programs to each.  When an Ethernet PDU session is set up, QCore assigns it to a spare device.  If it runs out of Ethernet devices, it rejects Ethernet PDU session creation.

An Ethernet PDU session may connect to multiple different MAC addresses on the UE side.  QCore does not allocate
MAC addresses.  To see which MAC addresses have been learned by the bridge from a given UE device / ethernet PDU session, run `bridge fdb show`.  For example
```sh
cargo test --test ngap_ethernet_session    # Run test that sends ethernet frames through the bridge
bridge fdb show br qcore_br0 dynamic       # See which MAC addresses have been learned by the bridge
                                           # Should include 02:02:02:02:02:01 and 02:02:02:02:02:02.
```

Linux bridges age out learned MAC addresses.  This is configurable using `brctl setageing`.  Currently, QCore is not smart enough to delete MAC addresses immediately from the bridge when a UE session is deleted.

As with IPv4 PDU sessions, the only way to relate an Ethernet session to a specific UE is by correlating INFO logs using the 'ue_id' as follows.

```
ue_id: 3921819296
  ...
  Sep 23 07:30:50.371 INFO Registering imsi-001011111111111
  ...
ue_id: 3921819296
  ...
  Sep 23 07:30:50.380 INFO Activate userplane session ethernet interface 9, local teid 0630f803, remote 127.0.0.2-00010001, 5QI=7
```

This means that the veth with interface index 9 was assigned to the UE with IMSI 001011111111111.  `ip link show` 
can be used to look up the interface index.


## Licence

The majority of code in this project is copyright (C) 2025 Nic Larkin and licensed under the APGL open source licence.  

AGPL is a copyleft licence.  If it doesn't suit your needs, please connect with me on LinkedIn and we can look into getting you a licence agreement which does not place you under copyleft obligations.

The eBPF program code is licensed under the GPL.  


## Contributions

Please contact me on LinkedIn if you are interested in contributing.

