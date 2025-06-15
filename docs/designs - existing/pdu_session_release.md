When releasing a PDU session, we first update the UE via Rrc Reconfiguration and then modify the F1 context to 
delete SRB2 and DRB 1.

## NGAP mode
```mermaid
sequenceDiagram
  participant GNB
  participant QC
  GNB->>QC: Nas Pdu Session Release Request
  QC->>GNB: Ngap Pdu Session Resource Release Command + Nas Pdu Session Release Complete  
  GNB->>QC: Ngap Pdu Session Resource Release Response
```


srsRAN does DU first and doesn't bundle rrc 

## F1AP mode
```mermaid
sequenceDiagram
  participant DU
  participant QC
  DU->>QC: Nas Pdu Session Release Request
  QC->>DU: F1 Ue Context Modification (DRB+SRB2) 
  DU->>QC: F1 Ue Context Modification Response (DU to CU Rrc Information)
  QC->>DU: Rrc Reconfiguration + Nas Pdu Session Release Command 
  DU->>QC: Rrc Reconfiguration Complete
  DU->>QC: Nas Pdu Session Release Complete
```

