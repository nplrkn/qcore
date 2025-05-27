In progress
-  fix SQN resync with Samsung
-  GUTI registration
   -  debug wireshark issue with MAC on registration accept
   -  SecurityContext should not call decode_nas_5gs_message()
   -  test GUTI registration reject with real UE and see if it reregisters with SUPI
   -  choose sensible cause codes (not 0) for all registration reject arms
   -  when mapping errors to cause codes, log the error text
   -  test successful GUTI registration with real UE
   -  use new newtypes like AmfIds and TMSI everywhere instead of .0
   -  impl display for GUTI / TMSI for INFO tracing (like "imsi-20893222" not [02, f8, 39...])
-  ASN.1 decode failed - Error { cause: Generic, msg: "Extended enum not implemented", context: ["CauseRadioNetwork", "Cause", "UeContextReleaseRequest", "InitiatingMessage", "F1apPdu"] }.  Wireshark: cause = radioNetwork / rl-failure-others (12).
-  Regression test using real AUTS calculation (to catch SQN handling changes).
-  Reduce occurance of heatmap spam log
-  set SD to 0, not omit it
 
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

