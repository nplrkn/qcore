```mermaid
sequenceDiagram
  participant DU
  participant CU
  participant Core
  DU->>CU: Nas Pdu Session Release Request
  CU->>Core: Nas Pdu Session Release Request
  Core->>CU: Ngap Pdu Session Resource Release Command + Nas Pdu Session Release Command  
  CU->>DU: F1 Ue Context Modification (DRB+SRB2) 
  DU->>CU: F1 Ue Context Modification Response (DU to CU Rrc Information)
  CU->>DU: Rrc Reconfiguration + Nas Pdu Session Release Command 
  CU->>Core: Ngap Pdu Session Resource Release Response
  DU->>CU: Rrc Reconfiguration Complete
  DU->>CU: Nas Pdu Session Release Complete
  CU->>Core: Nas Pdu Session Release Complete
```
