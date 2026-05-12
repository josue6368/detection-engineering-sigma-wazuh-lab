# detection-engineering-sigma-wazuh-lab
Built a detection engineering lab using Sigma-style rules and Wazuh SIEM. Created detections for failed logons, PowerShell discovery, and Active Directory group changes, then tested alerts against simulated activity and mapped detections to MITRE ATT&amp;CK.


# Detection Engineering Lab
## Overview

This project demonstrates the creation, testing, and validation of custom security detections using Windows event telemetry, Active Directory activity, PowerShell logging, Kali Linux attack simulation, and Wazuh SIEM monitoring.

The lab was built to simulate common attacker behaviors and validate how defensive detections can identify suspicious activity in a Windows enterprise environment. Custom Sigma-style rules and Wazuh XML detections were developed and mapped to the MITRE ATT&CK framework.

The project focuses on practical detection engineering workflows including:
* log generation
* telemetry validation
* SIEM detection tuning
* attack simulation
* Active Directory monitoring
* PowerShell visibility
* MITRE ATT&CK mapping

---

### Lab Architecture
#### Environment
| System                     | Purpose                            |
| -------------------------- | ---------------------------------- |
| Windows Server 2025 (DC01) | Active Directory Domain Controller |
| Windows 11 (WIN11-CLIENT)  | Domain-joined endpoint             |
| Kali Linux                 | Attack simulation platform         |
| Ubuntu Server              | Wazuh SIEM Server                  |

---

### Technologies Used
* Wazuh SIEM
* Windows Event Logging
* Active Directory
* PowerShell
* Sigma Rules
* Kali Linux
* SMB Authentication Testing
* VMware Workstation
* MITRE ATT&CK Framework

---

### Detection Objectives

The lab focused on building and validating detections for:

* brute force authentication attempts
* PowerShell discovery activity
* Active Directory group membership changes
* suspicious administrative behavior
* privilege escalation indicators

---

### Detection 1: Brute Force Authentication Detection
#### Objective

Detect repeated failed authentication attempts against a Windows system.
#### Attack Simulation

A Kali Linux system generated repeated SMB authentication failures against the Windows domain environment using invalid credentials.

#### Kali Linux Test Command
 ```
for i in {1..8}; do smbclient -L //192.168.88.140 -U "HOMELAB\\jsmith%WrongPassword123!" -m SMB3; done
```

**Kali Linux system generating repeated failed SMB authentication attempts against the Active Directory environment using invalid credentials.** <br />

<img width="650" height="196" alt="Screenshot 2026-05-11 144912" src="https://github.com/user-attachments/assets/366ea5f0-59cf-454e-832f-276d3fb91e05" />

---

### Windows Event Telemetry
#### Event ID
```
4625
```

### MITRE ATT&CK

```
T1110 - Brute Force
```

**Wazuh custom detection rule 100101 successfully identifying repeated failed authentication attempts associated with brute force behavior.** <br /> 
<img width="1209" height="7369" alt="Screenshot_12-5-2026_13735_192 168 88 133" src="https://github.com/user-attachments/assets/bae3b17c-36ba-4f50-bbf7-dbf2265ed95f" />

--- 

### Sigma-Style Rule

```
title: Multiple Failed SMB Logins
id: custom-failed-logins
status: experimental
description: Detects multiple failed Windows logon attempts that may indicate brute force or password guessing activity.
author: Josue Charry
date: 2026-05-08
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
fields:
  -EventID
  -TargetUserName
  -IpAddress
  -WorkstationName
falsepositives:
  - User mistyping password
  -Service account password mistmatch
  - Expired or cached credentials
level: medium
tags:
  - attack.credential_access
  - attack.t1110
```

<img width="698" height="517" alt="Screenshot 2026-05-11 140450" src="https://github.com/user-attachments/assets/4636fd7a-f35f-4c0b-8fdc-497b3301fbd0" />

---

### Wazuh Custom Detection Rule

<img width="694" height="515" alt="Screenshot 2026-05-11 150001" src="https://github.com/user-attachments/assets/88d7796b-f432-4fc8-acbc-0974980f3c6e" />

---

### Validation Result
The custom Wazuh rule successfully generated alerts after repeated failed SMB authentication attempts from the Kali Linux system.

#### Evidence Collected
* failed SMB authentication events
* Wazuh alert generation
* source IP visibility
* MITRE ATT&CK mapping
* brute force detection validation

---

### Detection 2: PowerShell Discovery Activity Detection
#### Objective

Detect suspicious PowerShell discovery behavior using Script Block Logging telemetry.

### PowerShell Logging Configuration

PowerShell Script Block Logging was enabled on the Windows 11 endpoint to improve visibility into PowerShell execution activity.

#### PowerShell Configuration Commands

```
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force

New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force
```

---

### PowerShell Discovery Commands Used
```
Get-Process | Select-Object -First 5

Get-LocalUser

Get-ComputerInfo | Select-Object CsName, WindowsProductName
```
<img width="699" height="557" alt="Screenshot 2026-05-11 152148" src="https://github.com/user-attachments/assets/f181426a-8b2a-4003-be28-ab4eb6325441" />


---

### Windows Event Telemetry
#### Event ID

```
4104
```

### MITRE ATT&CK

```
T1082 - Process Discovery
```
<img width="2372" height="3533" alt="Screenshot_12-5-2026_145757_192 168 88 133" src="https://github.com/user-attachments/assets/34e87fe1-8534-4caf-9a44-5ffca67554fe" />


---

### Sigma-Style Rule
<img width="694" height="532" alt="Screenshot 2026-05-11 151722" src="https://github.com/user-attachments/assets/319f4ae8-3734-4706-8d23-878e96bd615c" />

---

### Wazuh Custom Detection Rule
<img width="939" height="139" alt="Screenshot 2026-05-11 190234" src="https://github.com/user-attachments/assets/b81fb29b-6388-4d26-bc18-e7f9efd3d84e" />

---

### Validation Result

The Wazuh SIEM successfully detected PowerShell Script Block Logging events and generated a custom alert when discovery-related PowerShell activity occurred.

#### Evidence Collected
* PowerShell Event ID 4104
* ScriptBlockText visibility
* custom Wazuh detection alert
* MITRE ATT&CK mapping
* PowerShell telemetry validation

---
### Detection 3: Active Directory Group Membership Change Detection
#### Objective

Detect suspicious Active Directory group membership modifications that may indicate privilege escalation or account manipulation.

---
### Attack Simulation
An Active Directory group membership change was generated by adding a domain user to an administrative security group.

### PowerShell Command

```
Add-ADGroupMember -Identity "IT Support" -Members "jsmith"
```

<img width="668" height="193" alt="Screenshot 2026-05-12 120351" src="https://github.com/user-attachments/assets/83856934-dc2d-4af1-bded-ca92d3359a04" />


---

### Windows Event Telemetry
#### Event ID

```
4728
```

### MITRE ATT&CK
```
T1098 – Account Manipulation
```

<img width="1809" height="5543" alt="Screenshot_12-5-2026_121947_192 168 88 133" src="https://github.com/user-attachments/assets/f6480067-31c7-4042-b654-dfab023f10ef" />


--- 

### Sigma-Style Rule

<img width="694" height="524" alt="Screenshot 2026-05-12 112313" src="https://github.com/user-attachments/assets/11d4912b-c810-4019-a5f4-d501e265e7b7" />

---

### Wazuh Custom Detection Rule

<img width="701" height="199" alt="Screenshot 2026-05-12 115832" src="https://github.com/user-attachments/assets/b5cae42b-2980-44ba-a46d-df3eb6c0c15a" />


---

### Validation Result

The custom Wazuh rule successfully generated alerts when Active Directory group membership changes occurred within the lab environment.

### Evidence Collected
* Windows Event ID 4728
* group membership change visibility
* user and group tracking
* custom Wazuh alert generation
* MITRE ATT&CK mapping

---

## MITRE ATT&CK Coverage
| Detection                     | Technique            | ATT&CK ID |
| ----------------------------- | -------------------- | --------- |
| Brute Force Authentication    | Brute Force          | T1110     |
| PowerShell Discovery Activity | Process Discovery    | T1082     |
| AD Group Membership Changes   | Account Manipulation | T1098     |

---

## Key Skills Demonstrated
* Detection Engineering
* SIEM Monitoring
* Wazuh Rule Development
* Sigma Rule Creation
* Windows Event Analysis
* Active Directory Monitoring
* PowerShell Logging
* MITRE ATT&CK Mapping
* Threat Detection Validation
* Attack Simulation
* Security Operations
* Blue Team Analysis

---

## Lessons Learned
* Effective detection engineering depends heavily on proper telemetry configuration.
* PowerShell Script Block Logging significantly improves endpoint visibility.
* Active Directory monitoring is critical for detecting privilege escalation activity.
* Sigma-style detection logic can be translated into SIEM-specific detection rules.
* Wazuh custom rules provide flexible detection capabilities for Windows enterprise environments.

### Author
:floppy_disk: josue6368 <br/>
Cybersecurity Analyst | IT Professional































