# QCore

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

QCore is written in Rust.

## Quickstart

The quickest way to see QCore in action is to run its mainline test.
```sh
sudo ./setup-routing  # one-off - please read section below first
RUST_LOG=info cargo test attach -- --nocapture
```

To packet capture, run the following in parallel.
```sh
sudo tcpdump -w qcore.pcap -i any port 38472 or port 2152 or src 10.255.0.1 or dst 10.255.0.1
```

In Wireshark, select Edit--Preferences--Protocols--NAS-5GS--"Try to detect and decode 5G-EA0 ciphered messages".

## OpenAirInterface demo

QCore interoperates with the OpenAirInterface DU and UE simulator - step-by-step instructions [here](./docs/openairinterface_testing/README.md).

## Configuring and running QCore

Before you embark on running QCore in some other context, the key thing to bear in mind is this: it's not going to work first time and is likely to need a code change :-).  

Right now, QCore is very much incomplete, with plenty of hard-coded protocol fields, missing features, and other limitations, any of which could throw up interop problems.

The good news is that QCore is quick to enhance and I want to make it useful to you, with your help.  Please share the problems you run into as a Github issues, and make sure to get a packet capture.

### sims.toml

QCore reads SIM credentials from the file `sims.toml` in the current working directory.  Start with the sample file in the root of this project.  

### Command-line configuration

Run with the `--help` argument to see the command-line configuration options.

## About the routing setup

The `setup-routing` script makes a few Linux routing changes with root permissions, most notably adding a route 
to the 10.255.0.0/24 network and enabling Linux IP forwarding.  Please check that it is not going to interfere with your routing setup.

The purpose of these changes is to create a separate IP subnet for 5G UEs.  The UE subnet is reached via a tun interface.  

iptables and the rest of the Linux routing toolkit are at your disposal for associating routing policies to this tun device, and adding NAT.  

### UE-to-UE routing

QCore hairpins UE-to-UE packets through the Linux kernel IP stack, which means you can use iptables to block some/all UE-to-UE routing paths.  

By default, Linux routing generates ICMP Redirect in the case of UE-to-UE packet hairpinning - correctly so, but not what we want in our case.  The script therefore disables transmission of ICMP Redirect over our tun device. 

Hairpinned packets appear twice in tcpdump.  You can see this by running `RUST_LOG=info cargo test two_ues -- --nocapture` in parallel with the above tcpdump invocation.

## Licence

This project is licensed under the APGL open source licence.  

AGPL is a copyleft licence.  If it doesn't suit your needs, please connect with me on LinkedIn and we can look into getting you a licence agreement which does not place you under copyleft obligations.

## Contributions

Contributions to this project are welcome.  You'll need to sign our Contributor License Agreement.

