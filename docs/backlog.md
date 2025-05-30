In progress

-  Session establishment with real phone
   -  OnePlus
   -  Samsung
   -  Motorola

-  NAS library crashes with unknown IEI (max number of packet filter??) on PDU session establishment (?) - see ies-moto.pcap 

-  GUTI registration
   -  test successful GUTI registration with real UE
   -  in case of unknown GUTI, do identity request
-  ASN.1 decode failed - Error { cause: Generic, msg: "Extended enum not implemented", context: ["CauseRadioNetwork", "Cause", "UeContextReleaseRequest", "InitiatingMessage", "F1apPdu"] }.  Wireshark: cause = radioNetwork / rl-failure-others (12).
-  Regression test using real AUTS calculation (to catch SQN handling changes).
 - remaining SQN failure - with different SIM, with long SQN (top byte 01 not 00)?
 - test script should check there are no further messages when a mock is dropped

Performance
- iperf framework
- Release build perf profiling + tuning
- Reduce memcpy

Persistence
- Paging continuity

Function gaps
- Deregistration accept
- Idle / paging
- SQN
- Session deletion
- UE static IP
- Registration timeout and refresh
- PDCP Rx reordering
- Obey DL DATA DELIVERY STATUS backpressure (desired buffer size)
- PDCP retransmission for RLC Am
- Time out during procedures
- UE AMBR
- Transport key for SIM creds
- SUCI
- NEA2 ciphering
- Processing of UE measurements - detect when UE changes cell
- Uplink integrity validation for RRC / NAS
- Handling of PDCP control packets
- Handling of uplink PDCP sequence number out or order / gaps
- Negative testing of rejections and protocol errors
- RRC Inactive
- >1 PDU session per UE
- >1 DU

Tidying + refactoring
- message logs in both test framework and QCORE debug should use consistent F1 / RRC / NAS prefix
- merge nas_context.rs and security_context.rs
- simplify xxap 

Regression tests
- downlink packet checking of fields e.g. GTP payload length
- dl delivery status packet with / without payload
- tcp out through NAT masquerade
- stats (add new QCore pub method)

