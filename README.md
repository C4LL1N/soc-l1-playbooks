# soc-l1-playbooks
PB-SOC1-001: Phishing Email Analysis: zgodnie z [MITRE ATTACKS](https://attack.mitre.org/techniques/T1566/)
## SEKCJA NARZĘDZI (Appendix per playbook)

| KATEGORIA       | NARZĘDZIA                                      |
|-----------------|-----------------------------------------------|
| SIEM            | Splunk / Sentinel / QRadar / Elastic          |
| EDR             | CrowdStrike / Defender / S1 / CB              |
| Email Security  | Proofpoint / Mimecast / Defender              |
| Sandbox         | Any.Run / Joe Sandbox / Hybrid Analysis       |
| Threat Intel    | VirusTotal / OTX / MISP / ThreatFox           |
| URL Analysis    | URLScan.io / URLhaus / PhishTank              |
| IP Reputation   | AbuseIPDB / Talos / Shodan / Censys           |
| SOAR            | XSOAR / Phantom / Shuffle / TheHive           |
| Ticketing       | ServiceNow / Jira / TheHive                   |
| Network         | Zeek / Suricata / Wireshark                   |
| Forensics       | Velociraptor / KAPE / Volatility              |

---

## Key Performance Indicators (KPI)

### Per Playbook tracking

- MTTD (Mean Time to Detect): od wystąpienia do alertu  
- MTTT (Mean Time to Triage): od alertu do rozpoczęcia analizy  
- MTTR (Mean Time to Respond): od alertu do containment  
- False Positive Rate: % FP vs TP  
- Escalation Rate: % eskalowanych do L2  
- Recurrence Rate: % powracających incydentów tego samego typu  

### Cele

- **MTTT:** < 15 minut  
- **MTTR:** < 60 minut (P1), < 4h (P2), < 24h (P3)  
- **False Positive Rate:** < 30% (docelowo < 15%)  

---

## TEMPLATE DO ZAMKNIĘCIA

Closing Notes Template
═══════════════════════

Alert ID: [ID]
Classification: True Positive / False Positive / Benign True Positive
Category: Phishing / Malware / Brute Force / ...
Severity: Critical / High / Medium / Low
Summary: [1-2 zdania co się stało]
Root Cause: [Co było przyczyną]
Impact: [Kto/co zostało dotknięte]
Actions Taken: [Lista podjętych akcji]
IOCs Extracted: [Lista IOC dodanych do blocklist/TI]
Recommendations: [Zalecenia — tuning rule, user training, etc.]
Escalated: Yes/No → [Do kogo]
Time Spent: [minuty]
Analyst: [Imię]


---

## EVIDENCE COLLECTION

### Wymagane dowody do ticketu

- Screenshot emaila (treść + nagłówki)
- Pełne nagłówki (raw format)
- Lista IOC (IP, domeny, URL, hash)
- Wyniki sandbox (raport PDF / link)
- Wyniki VirusTotal (linki)
- Lista dotkniętych użytkowników
- Proxy / web gateway logi (kto kliknął)
- EDR telemetry (jeśli applicable)
- Timeline zdarzeń
- Podjęte akcje containment

---

## KRYTERIA ESKALACJI

### 🔴 ESKALUJ DO L2 NATYCHMIAST JEŚLI

- Potwierdzona kompromitacja credentials (C-level / admin)
- Malware execution potwierdzona na endpoincie
- Kampania phishingowa (>10 odbiorców, targeted)
- Spear phishing na C-level / VIP
- BEC z próbą przelewu
- Lateral movement po kliknięciu
- Powiązanie z aktywną kampanią APT (TI match)

---

### 🟡 ESKALUJ DO SOC MANAGERA JEŚLI

- Masowa kampania (>100 odbiorców)
- Potrzebna komunikacja z biznesem
- Media exposure risk

