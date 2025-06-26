<h1 align="center" style="border-bottom: none">
 <img src="docs/images/monolith.jpg" alt="drawing" width="200"/><br>QCore
</h1> 

QCore is an ultra-compact 5G Core, designed to minimise compute and power cost.  Its goal is to cater for small, data-only 5G networks in remote locations where weight and power are critical factors: 5G in a backpack / on a drone / in space.

To use it, you need to connect it to a gNB-DU / RU (gNodeB distributed unit and radio unit).

This project is at proof of concept stage, and I am looking for collaborators (with test kit!) to help improve and mature it.  Please do not hesitate to contact me via a GitHub issue or on LinkedIn if you are interested.

## Architecture overview

QCore is an all-in-one gNB-CU and 5G Core, running as a single Linux process.  It is designed as a monolith, without the standard network function decomposition of a 5G Core.  It has no internal protocol interfaces (no SBI), and a single UE context.  If you go looking in the source code for, say, an AMF, or a gNB-CU-UP... you won't find one.

The three external interfaces of QCore are:
-  the F1-C SCTP interface with the DU
-  the F1-U GTP interface with the DU
-  the N6 IP interface that connects UEs to the outside world.

The motivation for the monolithic approach is to minimize control plane and userplane processing cost.  QCore avoids a lot of the usual network hops, context switches, database accesses and (de)serialization.  As well as performance, its minimalist design also has side benefits in the areas of ease of orchestration, security, and simplicity / speed of development. 

QCore is written in Rust, and has an eBPF userplane. 

## Quickstart

The quickest way to see QCore in action is to run its mainline test.

### Set up environment
Install Rust.

```sh
cargo install bpf-linker
rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu
```

### Configure routing + network interfaces
For safety please read the [section below](#about-the-routing-setup) first.
```sh
sudo apt install iptables
sudo ./setup-routing
```

### Run attach test
```sh
RUST_LOG=info cargo test --test attach -- --nocapture
```

To packet capture, run the following in parallel.
```sh
sudo tcpdump -w qcore.pcap -i any sctp or port 2152 or host 10.255.0.1
```

Once the test has finished, hit Ctrl-C to exit tcpdump, then open `qcore.pcap` in Wireshark.  In Wireshark, select Edit--Preferences--Protocols--NAS-5GS--"Try to detect and decode 5G-EA0 ciphered messages".

## OpenAirInterface and srsRAN demos

QCore interoperates with OpenAirInterface and srsRAN.  Each of these two open source projects provides a gNB-DU and UE simulator.  

See the [OpenAirInterface demo walkthrough](./docs/OpenAirInterface-testing/README.md) and the [srsRAN demo walkthrough](./docs/srsRAN-testing/README.md).

## Configuring and running QCore

Before you embark on running QCore in some other context, the key thing to bear in mind is this: it's not going to work first time and is likely to need a code change :-).  

Right now, QCore is very much incomplete, with plenty of hard-coded protocol fields, missing features, and other limitations, any of which could throw up interop problems.

The good news is that QCore is quick to enhance and I want to make it useful to you, with your help.  Please share the problems you run into as a Github issues, and make sure to get a packet capture.

### Command-line configuration

Run with the `--help` argument to see the command-line configuration options.

### sims.toml

QCore reads SIM credentials from a file.  By default it uses `sims.toml` in the current working directory - see the sample file in the root of this project.  

Pass `--sim-cred-file` to read from a different file location.

## About the routing setup

The `setup-routing` script makes several Linux routing changes with root permissions.  Please check that it is not going to interfere with your routing setup.

The purpose of these changes are to 
-  Create a separate private IP subnet for 5G UEs.  The script enables forwarding to/from this subnet over the 'ue' tun interface, including NAT for packets leaving out of eth0.
-  Enable the QCore eBPF code to flexibly inject packets into Linux routing.  

### UE-to-UE routing

QCore hairpins UE-to-UE packets through the Linux kernel IP stack, which means you can use iptables to block some/all UE-to-UE routing paths.  

By default, Linux routing generates ICMP Redirect in the case of UE-to-UE packet hairpinning - correctly so, but not what we want in our case.  The script therefore disables transmission of ICMP Redirect over our tun device. 

### veth pair

By default, QCore receives downlink packets towards UE over a veth pair.  This is to ensure that the full Linux packet forwarding process
(including NAT and policy) completes before the packet gets intercepted by the QCore eBPF code.   

## Licence

The majority of code in this project is copyright (C) 2025 Nic Larkin and licensed under the APGL open source licence.  

AGPL is a copyleft licence.  If it doesn't suit your needs, please connect with me on LinkedIn and we can look into getting you a licence agreement which does not place you under copyleft obligations.

The eBPF program code is licensed under the GPL.  

## Contributions

Contributions to this project are welcome.  You'll need to sign our Contributor License Agreement.

