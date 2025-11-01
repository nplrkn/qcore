# On LAN UE addresses and DHCP

## Overview

On-LAN UE addresses allow us to carry out transfer and failover of individal UE addresses between nodes, without resorting to routing protocols such as BGP.

Using DHCP allows QCore to pick non-clashing on-LAN UE addresses that co-exist with whatever else might be living on the LAN.

In the standards, 5G Core DHCP operation is covered mostly in 3GPP TS29.561.


## Acting as a DHCP relay

A DHCP client has extremely unusual IP behaviour that is not supported by normal sockets.  It needs to send IP packets 
from source address 0.0.0.0, and receive unicast packets addressed to an IP that the local host does not own (yet). 

To avoid the implementation difficulties here, QCore plays the role of a DHCP relay towards the DHCP server.  Unlike
a DHCP client, a DHCP relay has entirely orthodox IP behaviour.

Normally, a DHCP relay has real DHCP clients behind it.  In our case, we simulate these.

QCore has the non-standard behaviour of performing DHCP renewals from its DHCP relay IP address.  Normally, a DHCP 
renewal should flow directly between the DHCP client and the server, cutting the relay out of the loop.  

This may turn out to be problematic, depending on how fussy DHCP servers turn out to be.  To manage the risk here, QCore
performs a DHCP self test on startup.


## Static IPs and DHCP reservation

Rather than have static address config in the QCore configuration, we believe it will typically be more streamlined for enterprises to manage UE IP addresses via their DHCP infrastructure.  

QCore assumes that DHCP server will be able to create IP address reservations based off 6-byte client identifiers (interpreting them as MAC addresses).  It forms DHCP client identifiers a MAC with the prefix 02 followed by the rightmost 10 digits of IMSI.  For example, IMSI 00101234554321 -> 00101>>1234554321<< -> MAC 02:12:34:55:43:21.

Search for the function `ue_dhcp_identifier` and read its comment for more on this. 


## Use of Linux ARP Proxy and /32 routes

QCore uses a netlink socket to program a /32 route for each UE.  Linux ARP proxy function detects theses routes and responds to 
ARPs for any address for which it has such a route.


## Other techniques

In the current design, each UE has its own route.  We also looked at giving each UE an individal Linux device - MACVLAN, IPVLAN, or veth.  

In the case of MACVLAN + IPVLAN, processes in the host namespace cannot send/receive packets over these links.  This is an awkward and error-prone restriction that would impede development or testing.

The veth solution is a probably viable alternative method.  In the absence of VLANs, it involves moving eth0 onto a Linux bridge - which seems fragile because it transiently disconnects the host.


