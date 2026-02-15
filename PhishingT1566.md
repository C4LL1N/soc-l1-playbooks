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

## Kroki Analizy: 
## KROKI ANALIZY (Step-by-Step)

---

### KROK 1: INITIAL TRIAGE (0–5 min)

- Odczytaj alert / zgłoszenie  
- Zweryfikuj podstawowe dane:
  - Nadawca (From / Return-Path / Envelope Sender)
  - Odbiorca (kto i ile osób)
  - Temat wiadomości
  - Timestamp
  - Czy email został dostarczony czy zablokowany?

- Sprawdź, czy to znany False Positive (FP database)
- Przypisz wstępny severity
- Otwórz ticket w systemie (ServiceNow / Jira / TheHive)

---

### KROK 2: HEADER ANALYSIS (5–10 min)

- Pobierz pełne nagłówki emaila (full headers)
- Przeanalizuj:
  - SPF → Pass / Fail / SoftFail / None
  - DKIM → Pass / Fail
  - DMARC → Pass / Fail / Policy
  - Return-Path vs From (spoofing check)
  - Received headers (ścieżka dostarczenia)
  - X-Originating-IP
  - Message-ID (anomalie?)

- Narzędzia:
  - MXToolbox Header Analyzer
  - Google Admin Toolbox
  - Własny parser w SOAR

---

### KROK 3: SENDER REPUTATION (ok. 5 min)

- Sprawdź domenę nadawcy:
  - WHOIS (data rejestracji — nowa domena = 🚩)
  - VirusTotal
  - AbuseIPDB (IP nadawcy)
  - Talos Intelligence
  - URLhaus / PhishTank

- Sprawdź lookalike / typosquatting:
  - np. `micros0ft.com`, `paypa1.com`

---

### KROK 4: CONTENT ANALYSIS (5–10 min)

#### Analiza treści emaila

- Urgency language („natychmiast”, „konto zablokowane”)
- Grammar / spelling errors
- Prośba o credentials / dane osobowe
- Prośba o przelew / zmianę konta bankowego (BEC)
- Podszywanie się pod managera / C-level

#### Analiza linków (BEZ KLIKANIA)

- Hover / defang URL
- URLScan.io
- VirusTotal
- Any.Run / Joe Sandbox (URL scan)
- Sprawdzenie redirectów
- Porównanie wyświetlanego tekstu vs rzeczywisty URL

#### Analiza załączników (BEZ OTWIERANIA)

- Nazwa pliku i rozszerzenie (double extension? np. `.pdf.exe`)
- Hash (MD5 / SHA256) → VirusTotal
- Sandbox detonation (Any.Run / Hybrid Analysis / Joe Sandbox)
- Typ MIME vs rozszerzenie
- Makra w Office (olevba)

---

### KROK 5: IMPACT ASSESSMENT (ok. 5 min)

- Ustal zakres:
  - Ile osób otrzymało emaila? (email gateway search)
  - Kto kliknął link? (proxy / web gateway logs)
  - Kto otworzył załącznik? (EDR telemetry)
  - Kto podał dane? (credential harvesting?)
  - Czy są powiązane alerty endpointowe? (EDR)

- Sprawdź w SIEM:
  - Korelacja po nadawcy / domenie / IP / URL / hash
  - Inne alerty od tych samych użytkowników
  - Network connections do podejrzanych domen

---

### KROK 6: CONTAINMENT (jeśli potwierdzone)

#### Email

- Usuń email ze wszystkich skrzynek (purge / recall)
- Zablokuj nadawcę na email gateway
- Dodaj domenę / URL / hash do blocklist

#### Network

- Zablokuj URL / domenę na proxy / firewall
- Zablokuj IP na firewall
- Dodaj do DNS sinkhole

#### Endpoint (jeśli kliknięcie / otwarcie)

- Izoluj endpoint (EDR network isolation)
- Uruchom pełny skan
- Sprawdź procesy i persistence

#### Identity (jeśli kompromitacja credentials)

- Wymuś reset hasła
- Revoke active sessions / tokens
- Włącz lub zweryfikuj MFA
- Sprawdź ostatnie logowania

## Mitigations: 

<img width="1361" height="507" alt="2026-02-16_00-21" src="https://github.com/user-attachments/assets/6c2033fa-9dfa-4e87-ac9e-fde6ba26ea0c" />







