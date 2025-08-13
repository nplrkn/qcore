# QCore routing setup

## UE IP addresses

QCore supports a single /24 UE IP subnet that defaults to 10.255.0.0/24.  To change this, you need to edit `setup-routing` and pass the `ue-subnet` command line parameter.

## UE-to-UE routing

QCore hairpins UE-to-UE packets through the Linux kernel IP stack, which means you can use iptables to block some/all UE-to-UE routing paths.  

By default, Linux routing generates ICMP Redirect in the case of UE-to-UE packet hairpinning - correctly so, but not what we want in our case.  The `setup-routing` script disables transmission of ICMP Redirect over our tun device. 

## veth pair

By default, QCore receives downlink packets towards UE over a veth pair.  This is to ensure that the full Linux packet forwarding process (including NAT and policy) completes before the packet gets intercepted by the QCore eBPF code.   
