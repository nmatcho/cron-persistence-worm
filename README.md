# cron-persistence-worm
Investigated a Linux incident where a malicious cron job attempted to maintain persistence by executing a worm-like bash script stored in /dev/shm. Detected through audit log analysis of unusual process activity and command execution.
# 🧩 Azure Linux VM Compromise Investigation  
**Analyst:** Nic Matcho  
**Date:** October 19–20, 2025  
**Incident ID:** IR-2025-10-19-LINUX-ASTATS  
**Classification:** Confirmed Compromise (Malware – Worm Behavior)  

---

## 🗂️ Table of Contents
1. [Overview](#overview)
2. [Initial Discovery](#initial-discovery)
3. [Investigation Steps](#investigation-steps)
    - [First Glance](#first-glance)
    - [Second Glance](#second-glance)
    - [Expanded Search](#expanded-search)
    - [File System Investigation](#file-system-investigation)
4. [Malicious Behavior Analysis](#malicious-behavior-analysis)
5. [Lateral Movement and Worm Indicators](#lateral-movement-and-worm-indicators)
6. [Response Actions](#response-actions)
7. [Findings Summary](#findings-summary)
8. [Lessons Learned](#lessons-learned)

---

## Overview
A huge network activity spike at midnight on October 20 launched a threat hunting campaign to uncover the cause. During the investigation of Microsoft Sentinel data sources, a Linux virtual machine named compromised-linux-vm (NAME REDACTED FOR PRIVACY) was identified exhibiting **high-volume outbound SSH scanning behavior** and evidence of **malicious script execution** within `/dev/shm` — a volatile memory-based directory often abused by attackers.

The investigation uncovered:
- 400K+ network events to AWS IP ranges.
- Over 50K invocations of a suspicious binary (`/dev/shm/astats -scan ssh 1 az`).
- Malicious Bash and cron scripts establishing persistence.
- Sentinel alerts for **lateral movement**, suggesting worm-like propagation.

The VM was confirmed **compromised** and isolated for further analysis.

---

## Initial Discovery

**Data Source:** `AzureNetworkAnalyticsIPDetails_CL`  
**Initial Query:**
```kql
AzureNetworkAnalyticsIPDetails_CL
| where PublicIPDetails_s == "amazon data services Ireland limited"
| summarize WhatIsGoingOn = count()
````

**Result:**

* 441,090 interactions with **Amazon Data Services Ireland Limited** within 24 hours.

**Interpretation:**
Unusual volume of outbound connections suggested command-and-control (C2) or scanning behavior.
Further investigation was warranted.

> ![Screenshot 1 – Initial Query Results](path/to/screenshot1.png)

---

## Investigation Steps

### First Glance

Focused on IPs beginning with `34.243` (AWS Ireland range).
Queried the **DeviceNetworkEvents** table for correlation.

```kql
DeviceNetworkEvents
| where RemoteIP contains "34.243"
```

Identified consistent interactions from:

```
compromised-linux-vm
```

Discovered repeated executions of:

```
/dev/shm/astats -scan ssh 1 az
```

**Count:** 6,434 executions.

---

### Second Glance

Expanded query to confirm scale and timeline:

```kql
DeviceNetworkEvents
| where RemoteIP contains "34.243"
| where DeviceName == "compromised-linux-vm"
| where InitiatingProcessCommandLine contains "/dev/shm/astats -scan ssh 1 az"
| summarize WhatIsGoingOn = count()
```

**ChatGPT analysis summary:**

* `/dev/shm` use indicates in-memory stealth.
* `-scan ssh` implies network reconnaissance.
* Behavior consistent with malware performing **SSH brute-force propagation**.

---

### Expanded Search

Querying a broader IP range (`34.24`) revealed:

```kql
DeviceNetworkEvents
| where RemoteIP contains "34.24"
| where DeviceName == "compromised-linux-vm"
| where InitiatingProcessCommandLine contains "/dev/shm/astats -scan ssh 1 az"
| summarize WhatIsGoingOn = count()
```

**Result:** 52,522 instances in 24 hours.

> ![Screenshot 2 – Expanded Network Events](path/to/screenshot2.png)

---

## File System Investigation

Queried **DeviceFileEvents** to identify file operations:

```kql
DeviceFileEvents
| where DeviceName == "compromised-linux-vm"
| project TimeGenerated, InitiatingProcessCommandLine
```

### Exhibit A

```bash
bash -c 'cd "/dev/shm" && if [ ! -f "w.sh" ]; then cat > "w.sh" && chmod +x w.sh; fi'
```

**Analysis:**

* Creates `/dev/shm/w.sh` in memory.
* Indicates script delivery (possibly downloaded via pipe).
* Classic malware staging behavior.

### Exhibit B

```bash
crontab -
```

**Analysis:**

* Likely writes malicious cron jobs via stdin.
* Used for persistence — common in Linux malware.

### Exhibit C

```bash
bash -c '
PATH=$PATH:/usr/bin:/usr/local/bin
CRON="$(crontab -l 2>/dev/null || true)"
if ! echo "$CRON" | grep -F '/dev/shm/w.sh "astats" "netai" "kstats" "ssh 1 az"' >/dev/null 2>&1; then
  (echo "$CRON"; echo '@reboot  /dev/shm/w.sh "astats" "netai" "kstats" "ssh 1 az"'; echo '0 * * * * cd "/dev/shm" && ./w.sh "astats" "netai" "kstats" "ssh 1 az"') | crontab -
fi
'
```

**Analysis:**

* Confirms **persistence setup** via cron.
* Ensures `w.sh` executes hourly and at reboot.
* Typical self-replication logic used in worms.

### Exhibit D

```bash
bash -c "ps aux | grep astats | grep -v grep | wc -l"
```

**Analysis:**

* Counts running `astats` processes.
* Likely used by malware to prevent duplicate instances.

> ![Screenshot 3 – DeviceFileEvents Evidence](path/to/screenshot3.png)

---

## Malicious Behavior Analysis

| Indicator                                  | Description                                         | Severity     |
| ------------------------------------------ | --------------------------------------------------- | ------------ |
| `/dev/shm/astats -scan ssh`                | SSH port scanning tool or worm module               | **Critical** |
| `/dev/shm/w.sh`                            | Malicious script staging/persistence                | **High**     |
| `crontab -`                                | Persistence mechanism                               | **High**     |
| `/usr/bin/apt-key --readonly verify`       | Possibly used by system processes; context required | **Medium**   |
| Repeated network events to AWS Ireland IPs | External scanning / lateral spread                  | **Critical** |

**Behavior Summary:**

* Worm-like SSH scanning.
* Cron-based persistence.
* In-memory execution (avoids disk logs).
* Likely spreading to other VMs over the same network.

---

## Lateral Movement and Worm Indicators

Microsoft Sentinel generated **Lateral Movement** alerts for the same VM.

This aligns with:

* SSH scan targets (`-scan ssh 1 az`)
* Hourly cron-based re-execution
* Potential credential reuse attempts across internal Azure network

> ![Screenshot 4 – Defender Alert](path/to/screenshot4.png)

---

## Response Actions

1. **Isolated the VM** in Azure Security Center to prevent further spread.
2. **Ran malware scans** to verify infection scope.
3. **Correlated Defender alerts** to confirm lateral movement behavior.
4. **Communicated with VM owner** — confirmed owner was active during event but unaware of `astats` activity.
5. **Documented and preserved evidence** (screenshots, queries, command logs).

---

## Findings Summary

| Category              | Details                                                                      |
| --------------------- | ---------------------------------------------------------------------------- |
| **Root Cause**        | Compromised Linux VM executing malicious in-memory scripts                   |
| **Primary Indicator** | `/dev/shm/astats -scan ssh 1 az`                                             |
| **Persistence**       | Cron jobs calling `/dev/shm/w.sh`                                            |
| **Propagation**       | SSH scanning across network and public IP ranges                             |
| **Detection Sources** | `DeviceNetworkEvents`, `DeviceFileEvents`, Microsoft Sentinel Alerts         |
| **Impact**            | Network noise, potential spread to other VMs, possible credential harvesting |
| **Status**            | VM isolated, investigation concluded                                         |

---

## Lessons Learned

* `/dev/shm` is a critical directory to monitor on Linux systems.
* Persistent cron entries often reveal post-exploitation activity.
* High-frequency outbound SSH traffic should always trigger investigation.
* Even test or lab VMs must have EDR monitoring and least-privilege SSH configurations.
* Manual threat hunting can reveal incidents **before alerts fully trigger**.

---

🛡️ **End of Report**
*Prepared by Nic Matcho – Azure Security Operations Analysis*
