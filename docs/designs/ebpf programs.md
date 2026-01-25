# EBPF programs

## Uplink

The uplink programs are responsible for intercepting a GTP encapsulated packet from the RAN and transmitting it on the N6 interface.  This may be an IP or Ethernet packet, and it may need to be looped back to another UE.

An XDP program is installed on whatever link connects the RAN to QCore.  It looks for GTP/UDP packets and decapsulate them.  This program is called `xdp_uplink_n3` or `xdp_uplink_f1u` depending on whether QCore is in F1 mode.

### Uplink Ethernet
In the case of Ethernet, the packet is injected into the Linux bridge via a redirect to the appropriate veth device egress.

```
                XDP program does decap and redirect  
                |                                              -------------------
                v   /== veth_ue_1_a egress ==> veth_ue_1_b ==> |                 |
== eth0 ingress ==> === veth_ue_2_a egress ==> veth_ue_2_b ==> |  qcore_br0      |
                    \== veth_ue_3_a egress ==> veth_ue_3_b ==> |                 |
                                                               -------------------
```

If the RAN is co-located in the same host as qcore, then the ingress interface is lo rather than eth0.

QCore attaches to the opposite side of the veth pair to the veth that is connected to the bridge.  I have not investigated whether it would be possible to use the same veth as the one connected to the bridge.

### Uplink IP

In the case of IP, the packet is injected into Linux routing.  The only way I have 
found to do this so far is to go via a TC program (`tc_uplink_redirect`), which redirect's to `qcoretun`'s ingress.  The XDP program sets a magic value in the packet metadata to allow TC program to quickly find the packets it needs to act on.

```
            XDP program does decap and sets magic metadata value  
                |   TC program picks up magic metadata value and redirects to qcoretun
                v   v                             ----------------------------
== eth0 ingress =====> | == qcoretun0 ingress ==> | Linux iptables, FIB, etc |
                                                  ----------------------------
```

If the RAN is co-located in the same host as qcore, then the ingress interface is lo rather than eth0.

The TC program also has a hack to clear the device checksum offload metadata, without which we hit a kernel bug when
doing UE to UE routing.   

## Downlink

### Downlink Ethernet

The Linux bridge transmits a frame out of one of its port devices.  These packets are picked up by XDP program
`xdp_downlink_n3_eth`, which encapsulates them in GTP.  Immediately afterwards, a TC program (`tc_downlink_eth_redirect`) redirects to qcoretun in order to get the GTP packet into Linux routing.  From there, it will be routed up over lo if the RAN is local, or out over an external link if the RAN is remote.

```
                                                          XDP program does encap 
                                                          |  TC program redirects to qcoretun
-----------------                                         v  v                          ----------------------------
|  qcore_br0    |== veth_ue_1_b ==> veth_ue_1_a ingress ====>| == qcoretun0 ingress ==> | Linux iptables, FIB, etc |
-----------------                                                                       ----------------------------
```

QCore does not currently support F1 mode for this path. 

### Downlink IP

In this case, Linux routes packets to the UE IP subnet.  In the default `setup-routing` script, this subnet is via veth0.  We pick them up via a TC program attached to that link (`tc_downlink_f1u` or `tc_downlink_n3`).

```
                                    TC program does encap and redirects to qcoretun
                                      |
-----------------                     v                         ----------------------------
| Linux routing |== veth0 ingress ===>|== qcoretun0 ingress ==> | Linux iptables, FIB, etc |
-----------------                                               ----------------------------
```

This is a TC rather than an XDP program for historical reasons.  It may make sense to change to a pair of XDP / TC programs, like the Ethernet case.

## Open design issues + questions

-   In three of the four paths above, we make use of TC redirect ingress to qcoretun to pass packets into Linux routing.  Is there the possibility to XDP_PASS into Linux routing instead without ever changing interfaces / going via a TC program, in one or more of these paths?

-  Is it possible to clear the checksum without go via a TC program?  (See 'uplink IP'.)
