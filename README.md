<h1 align="center" style="border-bottom: none">
 <img src="docs/images/monolith.jpg" alt="drawing" width="200"/><br>QCore
</h1> 

QCore is a free, ultra-compact private 5G Core, written in Rust, designed to minimise compute and power cost.  

It is simple to use, and significantly outperforms other single-node 5G cores thanks to its monolithic architecture.  

Using a tiny 30MB executable, it can handle 30,000 control plane messages per second on a single CPU core ([details](docs/Open5GS-comparative-load-testing.md)).  The userplane is implemented using eBPF for gigabit/s throughput.

It has been tested and works well with several Android phones (Samsung, OnePlus and Oppo) but remains at an early stage of maturity.  

I would welcome collaborators to help improve and mature it.  Please contact me via a GitHub issue or on LinkedIn if you are interested.

## Architecture overview

The three external interfaces of QCore are:
-  the N2 (NG-C) SCTP interface with the gNodeB
-  the N3 (NG-U) GTP interface with the gNodeB
-  the N6 IP interface that connects UEs to the outside world.

Whereas most 5G cores consist of many different services, QCore is a single Linux executable.  It is designed as a monolith, without the standard network function decomposition of a 5G Core.  It has no internal protocol interfaces (no SBI), and a single UE context.  

The motivation for the monolithic approach is to minimize control plane processing cost.  QCore avoids a lot of the usual network hops, context switches, database accesses and (de)serialization.  As well as performance, its minimalist design also has major benefits in the areas of ease of orchestration, security, and simplicity / speed of development. 


## F1 mode

QCore supports "F1 mode", in which it takes on the role of a gNB-CU in addition to the 5G Core.  The idea is to allow an organization with an existing gNB-DU appliance to extend their solution to offer a complete private 5G in a box by running QCore on the same node.

When running in F1 mode, QCore exposes the F1-C and F1-U interfaces, instead of N2 and N3.


## Quickstart

The quickest way to see QCore in action is to [run its mainline test](#run-the-mainline-test) and look at the packet capture.

You might also want to try the [srsRAN demo](./docs/srsRAN-testing/README.md).

### Run the mainline test

#### Set up environment
Before you start, install Rust and read the [section below on the routing setup](#about-the-routing-setup).

```sh
# Install build dependencies
cargo install bpf-linker
rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu

# Configure QCore routing setup 
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
RUST_LOG=info cargo test --test ngap-attach -- --nocapture
```

Once the test has finished, hit Ctrl-C to exit tcpdump, then open `qcore.pcap` in Wireshark.  In Wireshark, select Edit--Preferences--Protocols--NAS-5GS--"Try to detect and decode 5G-EA0 ciphered messages".


## Configuring and running QCore

### sims.toml

QCore reads SIM credentials from a file.  By default it uses `sims.toml` in the current working directory - see the [sample file](./sims.toml) in the root of this project.  

Pass `--sim-cred-file` to read from a different file location.

### Command-line configuration

The command line options `local-ip` and `ran-interface-name` govern the connection with the RAN. By default, QCore assumes the gNB / DU will connect over `eth0`.  

```sh
# By default QCore communicates with gNB over eth0.  
# In this case the gNB AMF address config should be set to the IP address of eth0. 
qcore --mcc 001 --mnc 06   

# For the case where the gNB is running in the same machine and network namespace as QCore.
# In this case, the gNB AMF address config should be set to 127.0.0.1.
qcore --mcc 001 --mnc 06 --local-ip 127.0.0.1 --ran-interface-name lo
```

Run with the `--help` argument to see all the command-line configuration options.

### Selection of external DN interface

QCore itself is not aware of the interface used to reach the outside world (that is, the Data Network, in 5G terms).  It injects all UE packets into Linux routing over `qcoretun`, and Linux routing then forwards each packet.  This includes UE-to-UE packets.

The `setup-routing` script sets up NAT connectivity over `eth0` by default (with an assumption that the default gateway is connected on this interface).  You can pass a different device name, for example:
```sh
./setup-routing enp113s0  # Set up iptables NAT for a default route via device enp113s0
```

### Linux Permissions

QCore installs an eBPF program on startup and needs the relevant Linux permissions to do so.  The easiest way to 
achieve this is to run it as root.

QCore routing setup also requires elevated permissions. 


## About the routing setup

The [`setup-routing`](./setup-routing) script makes several Linux routing changes with root permissions.  Please check that it is not going to interfere with your routing setup.

The purpose of these changes is to 
-  Create a separate private IP subnet for 5G UEs.  The script enables forwarding to/from this subnet over the 'ue' tun interface, including NAT for packets leaving out of eth0.
-  Enable the QCore eBPF code to flexibly inject packets into Linux routing.  

For more details, see [routing.md](./docs/routing.md).

## Licence

The majority of code in this project is copyright (C) 2025 Nic Larkin and licensed under the APGL open source licence.  

AGPL is a copyleft licence.  If it doesn't suit your needs, please connect with me on LinkedIn and we can look into getting you a licence agreement which does not place you under copyleft obligations.

The eBPF program code is licensed under the GPL.  

## Contributions

Contributions to this project are welcome.  You'll need to sign a Contributor License Agreement.

