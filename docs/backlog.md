# Backlog

## In progress
- Rejection of Registration Request from Security Mode Command if slice asked for is eMBB / SST 1 with "no network slices available"
  -  causes OnePlus phone to reregister with MIoT SST 3 / SD 0.
-  Unhandled RrcReestablishmentRequest
-  See f1ap-samsung.log.

- NGAP mode 
  - move ran_session_setup_phase1 + 2 out of ue_procedure.rs
  - if initial context setup request fails, 'unhandled message' and we don't save off the GUTI
  - Registration accept should piggyback on NGAP Initial Context Setup request
  - use different forwarding tables for NGAP vs F1AP 
  - DlDropUnknownUe incrementing when no phones attached
- Session establishment with real phone
   -  OnePlus 
      -  refuses to set up a session and sends a ServiceRequest
   -  OPPO 
      -  SQN resync not working - fixed??
      -  Identity Request not working - registration reject?
   -  Samsung (working)
   -  Motorola (working)
- "NG setup with GNB name" - log line - trace of bitvec global gnb ID is ugly 
- PDU session release command should flow on SRB 2, not SRB 1  
 
## Performance
- iperf framework
- Release build perf profiling + tuning
- Reduce memcpy

## Persistence
- Paging continuity
- SQN

## Function gaps
- Deregistration accept
- Update / Remove a DU's served cells on Du configuration update, F1 Remove, disconnection
- Large SCTP messages - e.g. unfiltered UE Capability Information
- Idle / paging
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

## Error handling
- Session setup with existing PDU session ID should not leave up old session.  Seen with OnePlus phone which repeated 
  its session setup request (with no intervening delete) after not liking the response.

## Tidying + refactoring
- reduce test boilerplate
- struct Config should be split into information that is used on startup (which doesn't need to be cloned), and information that is used by procedures (which does need to be cloned) 
- give rrc its own directory under ue_associated procedures
- avoid having to expect() on UeContext fields
- message logs in both test framework and QCORE debug should use consistent F1 / RRC / NAS prefix
- simplify xxap 

## Regression tests
- should check there are no further messages when a mock is dropped
- userplane testing of 18 bit PDCP sequence number
- using real AUTS calculation (to catch SQN handling changes).
- downlink packet checking of fields e.g. GTP payload length
- dl delivery status packet with / without payload
- tcp out through NAT masquerade
- stats (add new QCore pub method)
