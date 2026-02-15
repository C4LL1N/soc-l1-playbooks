# Phishing 
ID: T1566
Podtechniki:
T1566.001	Spearphishing Attachment
T1566.002	Spearphishing Link
T1566.003	Spearphishing via Service
T1566.004	Spearphishing Voice 


## METADATA

Playbook ID:        PB-SOC1-001

Nazwa:              Phishing Email Analysis

Wersja:             1.0

Autor:              C4LL1N

Klasyfikacja:       INTERNAL

MITRE ATT&CK:      T1566.001, T1566.002

Kill Chain Phase:   Delivery

Częstotliwość przeglądu: Co 90 dni

SLA:                15 min (initial triage), 60 min (resolution)

Powiązane playbooki: PB-SOC1-003 (Malware), PB-SOC1-007 (C2)

## TRIGGER CONDITIONS:

Źródła alertów:
├── Email Gateway (Proofpoint / Mimecast / Microsoft Defender)
├── Zgłoszenie użytkownika (phishing button / helpdesk ticket)
├── SIEM correlation rule
├── Threat Intel feed match
└── Sandbox detonation alert

## SEVERITY MATRIX:

<img width="689" height="356" alt="2026-02-16_00-11" src="https://github.com/user-attachments/assets/b3370eca-361f-4d34-8f85-0620f7f1f8bc" />

## Detection Strategy Według Mitre across Platform:

- AN0188 Unusual inbound email activity where attachments or embedded URLs are delivered to users followed by execution of new processes or suspicious document behavior. Detection involves correlating email metadata, file creation, and network activity after a phishing message is received.

- AN0189	Monitor for malicious payload delivery through phishing where attachments or URLs in email clients (e.g., Thunderbird, mutt) result in unusual file creation or outbound network connections. Focus on correlation between mail logs, file writes, and execution activity.

- AN0190	Detection of phishing through anomalous Mail app activity, such as attachments saved to disk and immediately executed, or Safari/Preview launching URLs and files linked from email messages. Correlate UnifiedLogs events with subsequent process execution.

- AN0191	Phishing via Office documents containing embedded macros or links that spawn processes. Detection relies on correlating Office application logs with suspicious child process execution and outbound network connections.

- AN0192	Phishing attempts targeting IdPs often manifest as anomalous login attempts from suspicious email invitations or fake SSO prompts. Detection correlates login flows, MFA bypass attempts, and anomalous geographic patterns following phishing email delivery.

- AN0193	Phishing delivered via SaaS services (chat, collaboration platforms) where messages contain malicious URLs or attachments. Detect anomalous link clicks, suspicious file uploads, or token misuse after SaaS-based phishing attempts.




