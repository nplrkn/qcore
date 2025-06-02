In progress

-  Session establishment with real phone
   -  OnePlus
   -  Samsung
   -  Motorola

-  retest
   -  NAS library crashes with unknown IEI (max number of packet filter??) on PDU session establishment (?) - see ies-moto.pcap 
   -  GUTI registration
   -  cause = radioNetwork / rl-failure-others (12).
 
-  remaining SQN failure - with different SIM, with long SQN (top byte 01 not 00)?
 
Performance
- iperf framework
- Release build perf profiling + tuning
- Reduce memcpy

Persistence
- Paging continuity

Function gaps
- In case of unknown GUTI, do identity request
- Deregistration accept
- PDU session release
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
- TODOs
- Handling of PDCP control packets
- Handling of uplink PDCP sequence number out or order / gaps
- Negative testing of rejections and protocol errors
- RRC Inactive
- >1 PDU session per UE
- >1 DU

Tidying + refactoring
- message logs in both test framework and QCORE debug should use consistent F1 / RRC / NAS prefix
- simplify xxap 
- get rid of patch_nas_for_oai_deregistration_security_header() and fail gracefully

Regression tests
- should check there are no further messages when a mock is dropped
- using real AUTS calculation (to catch SQN handling changes).
- downlink packet checking of fields e.g. GTP payload length
- dl delivery status packet with / without payload
- tcp out through NAT masquerade
- stats (add new QCore pub method)

