# Mainline attach flow
This is the mainline flow wherein a 5G UE connects to the RAN and 5G Core and sets up a PDU session.

## F1AP mode
The registration part of the procedure is implemented by InitialAccessProcedure::run() in [initial_access.rs](../../qcore/src/procedures/ue_procedures/initial_access.rs).

The session establishment part of the procedure is implemented by PduSessionEstablishmentProcedure::run() in [pdu_session_establishment.rs](../../qcore/src/procedures/ue_procedures/pdu_session_establishment.rs).

```mermaid
sequenceDiagram
  participant DU
  participant QC
  participant DN
  Note over DU,QC: Setup
  DU->>QC: SCTP connection
  DU->>QC: F1 Setup Request
  QC->>DU: F1 Setup Response
  Note over DU,QC: Registration
  DU->>QC: Rrc SetupRequest / F1 InitialUlRrcMessageTransfer 
  QC->>DU: Rrc Setup Response 
  DU->>QC: Nas Registration Request / Rrc Setup Complete 
  QC->>DU: Nas Authentication Request 
  DU->>QC: Nas Authentication Response
  QC->>DU: Nas Security Mode Command
  DU->>QC: Nas Security Mode Complete
  QC->>DU: Rrc Security Mode Command 
  DU->>QC: Rrc Security Mode Complete
  QC->>DU: Nas Registration Accept
  DU->>QC: Nas Registration Complete
  Note over DU,QC: Session Establishment
  DU->>QC: Nas Pdu Session Establishment Request
  QC->>DU: F1 Ue Context Setup Request
  DU->>QC: F1 Ue Context Setup Response
  QC->>DU: Nas PDU Session Establishment Accept / Rrc Reconfiguration 
  DU->>QC: Rrc Reconfiguration Complete 
  Note over DU,DN: Userplane data flows
  DU->>QC: F1U uplink data packet
  QC->>DN: IP packet
  DN->>QC: IP packet
  QC->>DU: F1U downlink data packet
```

The following are assumed: Rrc DlInformationTransfer / F1 DlRrcMessageTransfer; Rrc UlInformationTransfer / F1 UlRrcMessageTransfer.

## NGAP mode

```mermaid
sequenceDiagram
  participant GNB
  participant QC
  participant DN
  Note over GNB,QC: Setup
  GNB->>QC: SCTP connection
  GNB->>QC: NG Setup Request
  QC->>GNB: NG Setup Response
  Note over GNB,QC: Registration
  GNB->>QC: NG Initial UE Message + Nas Registration Request
  QC->>GNB: Nas Authentication Request 
  GNB->>QC: Nas Authentication Response
  QC->>GNB: Nas Security Mode Command 
  GNB->>QC: Nas Security Mode Complete
  QC->>GNB: Initial Context Setup Request
  GNB->>QC: Initial Context Setup Response
  QC->>GNB: Nas Registration Accept
  GNB->>QC: Nas Registration Complete
  Note over GNB,QC: Session Establishment
  GNB->>QC: NG Pdu Session Resource Setup Request  + Nas Pdu Session Establishment Accept
  QC->>GNB: NG Pdu Session Resource Setup Response
  Note over GNB,DN: Userplane data flows
  GNB->>QC: N3 uplink data packet
  QC->>DN: IP packet
  DN->>QC: IP packet
  QC->>GNB: N3 downlink data packet
```

The following are assumed: NG Uplink NAS transport / NG Downlink NAS transport.