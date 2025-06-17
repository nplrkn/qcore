# Mainline attach flow
This is the mainline flow wherein a 5G UE connects to the RAN and 5G Core and sets up a PDU session.

Depending on its mode, QCore plays the role of the Core+CU columns, or just the Core column.  

The following are assumed: 
- Rrc DlInformationTransfer / F1ap DlRrcMessageTransfer / Ngap Downlink NAS transport
- Rrc UlInformationTransfer / F1ap UlRrcMessageTransfer / Ngap Uplink NAS transport

```mermaid
sequenceDiagram
  participant DU
  participant CU
  participant Core
  participant DN
  Note over DU,Core: Setup
  CU->>Core: SCTP connection
  CU->>Core: NG Setup Request
  Core->>CU: NG Setup Response
  DU->>CU: SCTP connection
  DU->>CU: F1 Setup Request
  CU->>DU: F1 Setup Response
  Note over DU,Core: Registration
  DU->>CU: Rrc SetupRequest / F1 InitialUlRrcMessageTransfer 
  CU->>DU: Rrc Setup Response 
  DU->>CU: Nas Registration Request / Rrc Setup Complete 
  CU->>Core: NG Initial UE Message + Nas Registration Request
  Core->>CU: Nas Authentication Request 
  CU->>DU: Nas Authentication Request 
  DU->>CU: Nas Authentication Response
  CU->>Core: Nas Authentication Response
  Core->>CU: Nas Security Mode Command 
  CU->>DU: Nas Security Mode Command
  DU->>CU: Nas Security Mode Complete
  CU->>Core: Nas Security Mode Complete
  Core->>CU: Ngap Initial Context Setup Request
  CU->>DU: Rrc Security Mode Command 
  DU->>CU: Rrc Security Mode Complete
  CU->>DU: Rrc Ue Capability Enquiry 
  DU->>CU: Rrc Ue Capability Information
  CU->>Core: Ngap Initial Context Setup Response
  Core->>CU: Nas Registration Accept
  CU->>DU: Nas Registration Accept
  DU->>CU: Nas Registration Complete
  CU->>Core: Nas Registration Complete
  Note over DU,Core: Session Establishment
  DU->>CU: Nas Pdu Session Establishment Request
  CU->>Core: Nas Pdu Session Establishment Request
  Core->>CU: Ngap Pdu Session Resource Setup Request  + Nas Pdu Session Establishment Accept
  CU->>DU: F1ap Ue Context Setup Request
  DU->>CU: F1ap Ue Context Setup Response
  CU->>DU: Nas PDU Session Establishment Accept / Rrc Reconfiguration 
  Note over DU,DN: Uplink userplane established
  DU->>CU: Rrc Reconfiguration Complete 
  CU->>Core: Ngap Pdu Session Resource Setup Response 
  Note over DU,DN: Downlink userplane established
  DU->>CU: F1U uplink data packet
  CU->Core: N3 uplink data packet
  Core->>DN: IP packet
  DN->>Core: IP packet
  Core->>CU: N3 downlink data packet
  CU->>DU: F1U downlink data packet
```