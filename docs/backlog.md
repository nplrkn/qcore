In progress - SRS RAN demo
- Bugs
  -  Do not require SDAP downlink header
  -  OAI UE on receiving downlink packet 
     - [PDCP]   /home/npl/openairinterface5g/openair2/LAYER2/nr_pdcp/nr_pdcp_entity.c:74:nr_pdcp_entity_recv_pdu: fatal
     - [PDCP]   discard NR PDU rcvd_count=128, entity->rx_deliv 0,sdu_in_list 1
  -  ERRO Unhandled message F1RemovalRequest(F1RemovalRequest { transaction_id: TransactionId(1) })
  
High priority function gaps
- Deregistration accept
- Userplane stats
- Idle / paging
- SQN

Performance
- XDP userplane
- Release build perf profiling + tuning
- Check scaling to multiple threads
- Reduce memcpy

Persistence
- Paging continuity

Other function gaps
- Session deletion
- UE static IP
- Registration timeout and refresh
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
