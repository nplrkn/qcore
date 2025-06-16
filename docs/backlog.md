In progress

- Handle session release request

- NGAP mode 
  - Test with srsRAN
  - clean up uplink pipeline
  - use different forwarding tables for NGAP vs F1AP 
  - session release

-  Session establishment with real phone
   -  OnePlus
   -  Samsung
   -  Motorola
 
Performance
- iperf framework
- Release build perf profiling + tuning
- Reduce memcpy

Persistence
- Paging continuity

NGAP mode
- Registration accept should piggyback on NGAP Initial Context Setup request

Function gaps
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
- Time out during procedures - e.g. Authentication procedure uses T3560
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

Error handling
- Session setup with existing PDU session ID should not leave up old session.  This was seen with OnePlus phone which repeated 
  its session setup request (with no intervening delete) after not liking the response.

Tidying + refactoring
- avoid having to expect() on UeContext fields
- message logs in both test framework and QCORE debug should use consistent F1 / RRC / NAS prefix
- simplify xxap 
- get rid of patch_nas_for_oai_deregistration_security_header() and fail gracefully

Regression tests
- should check there are no further messages when a mock is dropped
- userplane testing of 18 bit PDCP sequence number
- using real AUTS calculation (to catch SQN handling changes).
- downlink packet checking of fields e.g. GTP payload length
- dl delivery status packet with / without payload
- tcp out through NAT masquerade
- stats (add new QCore pub method)

