# ⚠️ Podejrzany PowerShell – Playbook

## 🔔 Wyzwalacz alertu
Wykonanie PowerShell z:
- zakodowaną komendą (encoded command)
- download cradle (pobieranie z zewnętrznego źródła)
- flagami omijającymi zabezpieczenia (np. `-ExecutionPolicy Bypass`)

---

## 🔎 Kroki triage

1. Zidentyfikuj hosta i użytkownika, który uruchomił komendę  
2. Zdekoduj zakodowaną komendę (np. CyberChef – Base64 decode)  
3. Sprawdź, czy komenda pobiera coś z zewnętrznego URL  
   - Jeśli tak → sprawdź URL w VirusTotal  
4. Sprawdź proces nadrzędny (parent process)  
   - Czy PowerShell został uruchomiony przez:
     - Office (Word/Excel) ⚠️  
     - `cmd.exe`  
     - `wscript.exe` ⚠️  
   → To jest podejrzane  
5. Sprawdź, czy to znany skrypt administracyjny lub zaplanowane zadanie  

---

## ✅ Jeśli to legalna aktywność administracyjna

- Dodaj hash lub ścieżkę skryptu do whitelisty  
- Udokumentuj jako false positive  
- Zamknij alert  

---

## 🚨 Jeśli aktywność jest podejrzana / złośliwa

- ESKALUJ DO L2  
- Odizoluj endpoint  
- Zablokuj zewnętrzny URL/IP na firewallu  
- Sprawdź inne endpointy pod kątem podobnej aktywności  
- Sprawdź mechanizmy persistence i lateral movement  

---

## 📌 IOC do udokumentowania

- Pełna linia polecenia (po dekodowaniu)  
- Zewnętrzne URL/IP  
- Łańcuch procesów (parent → child)  
- Nazwa hosta i użytkownik  

---

## 🧠 Mapowanie MITRE ATT&CK

- T1059.001 – PowerShell  
- T1027 – Obfuscated/Compressed Files and Information  
- T1105 – Ingress Tool Transfer  
- T1204 – User Execution  
- T1566 – Phishing  
- T1547 – Boot or Logon Autostart Execution  
- T1021 – Remote Services  
