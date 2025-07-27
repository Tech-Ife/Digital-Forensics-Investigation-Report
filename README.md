# Digital Forensics Investigation: The Stolen Szechuan Sauce

##  Project Overview

This project formed part of my training during the February 2025 cohort at the Lighthouse Labs Cybersecurity Bootcamp. It contains a **comprehensive Digital Forensics Report and investigation findings** for the **simulated incident “The Stolen Szechuan Sauce.”**  

 As part of the project, I was provided with a set of forensic artifacts, including disk images, memory dumps, and network traffic logs (PCAP), and tasked with conducting a comprehensive digital forensics investigation. 
 
This hands-on simulation offered valuable insights into **malware behavior, attack vectors, persistence mechanisms, and lateral movement techniques**, all derived from analyzing digital evidence such as **disk images, memory dumps, and network packet captures (PCAPs)**.
 
---

##  Executive Summary

In this project, a malicious actor infiltrated a victim network using **RDP brute force** to compromise a Windows Server and Desktop. A malware payload named `coreupdater.exe` was discovered, which connected to known malicious infrastructure to exfiltrate data.

This investigation successfully reconstructed the sequence of the attack, identified affected systems, examined evidence of lateral movement, and validated the breach through digital artifacts. The report concludes with actionable recommendations aligned with the **NIST Cybersecurity Framework (CSF)** and **NIST SP 800-53**.

---

##  Methodology

The forensic workflow followed these stages:

1. **Image Analysis**: Inspected disk and memory images using FTKImager and Autopsy.
2. **Network Forensics**: Analyzed PCAP traffic with Wireshark.
3. **Malware Identification**: Verified malicious binaries via hash comparison and VirusTotal.
4. **Timeline Reconstruction**: Correlated timestamps from artifacts and logs.
5. **Threat Intelligence**: Used MITRE ATT&CK, AlienVault OTX, and VirusTotal intelligence.
6. **Reporting**: Compiled findings with recommendations.

---

##  Tools & Frameworks Used

- **FTK Imager**
- **Autopsy 4.21.0**
- **Wireshark**
- **Volatility Workbench**
- **EvtxECmd + Timeline Explorer**
- **VirusTotal**
- **MITRE ATT&CK**
- **NIST CSF & NIST SP 800-53**
- **AlienVault OTX**

---

##  Artifacts Analyzed

| Artifact Type          | Description                              |
|------------------------|------------------------------------------|
| Disk Image             | DC01 (Windows Server), Desktop (E01)     |
| Memory Dump            | DC01 and Desktop                         |
| PCAP File              | Case001 network traffic capture          |

---

##  Table of Findings

| Investigation Focus              | Key Findings |
|----------------------------------|--------------|
| **Server OS**                    | Windows Server 2012 R2 Standard |
| **Desktop OS**                   | Windows 10 Enterprise Eval |
| **Local Time (Server)**          | Pacific Standard Time |
| **Initial Entry Vector**         | RDP Brute Force from IP 194.61.24.102 |
| **Malware Used**                 | `coreupdater.exe` (Metasploit) |
| **Malware Capabilities**         | XOR obfuscation, persistence via registry/service |
| **Malicious IPs**               | 194.61.24.102 (Russia), 203.78.103.109 (Thailand) |
| **Data Exfiltration**            | `Loot.zip`, `Secret.zip` from FileShare |
| **Persistence Techniques**       | Registry autorun, Windows service install |
| **Attack Timeline**              | Sept 18–19, 2020 |
| **Network Layout**               | Server (10.42.85.10), Desktop (10.42.85.115), Gateway (10.42.85.0/24) |

---

##  Recommended Remediations (NIST CSF Aligned)

| NIST CSF Category               | Recommendation                                                   |
|--------------------------------|------------------------------------------------------------------|
| **Protect – Access Control**   | Implement Multi-Factor Authentication (MFA) for RDP              |
| **Protect – Maintenance**      | Apply OS and software security patches                          |
| **Protect – Identity Mgmt**    | Enforce strong, unique passwords and PAM policies               |
| **Detect – Anomalies & Events**| Enable and monitor event logs for RDP connections               |
| **Respond – Mitigation**       | Remove malware and revoke compromised credentials               |
| **Recover – Improvements**     | Update incident response plan and recovery protocols            |

---

##  Skills Gained

- Memory & disk image forensics
- Malware detection & analysis
- Network traffic analysis
- MITRE ATT&CK & threat intelligence mapping
- Writing professional cybersecurity investigation reports
- Leveraging open-source and enterprise forensic tools

---

##  Project Files

-  [Digital Forensics Report pdf](
  
---

## Artifacts 

[DC01 Disk Image (E01)](https://dfirmadness.com/case001/DC01-E01.zip)

[DC01 Memory file](https://dfirmadness.com/case001/DC01-memory.zip)

[Case 001 PCAP](https://dfirmadness.com/case001/case001-pcap.zip)

[Desktop Disk Image (E01)](https://dfirmadness.com/case001/DESKTOP-E01.zip)

[Desktop Memory file](https://dfirmadness.com/case001/DESKTOP-SDN1RPT-memory.zip) 

---

##  Screenshots

> Include screenshots of Autopsy interface, Wireshark flows, Volatility outputs, or registry paths showing persistence indicators. *(Optional but recommended for the GitHub preview.)*

---

##  References

- [MITRE ATT&CK TA0003 – Persistence](https://attack.mitre.org/tactics/TA0003/)
- [VirusTotal](https://www.virustotal.com/)
- [NIST SP 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [DFIR Madness - Original Case](https://dfirmadness.com/answers-to-szechuan-case-001/)
- [AlienVault OTX](https://otx.alienvault.com/)


  ---


##  Author

**Ifeanyi Christian Edeh**  
- [LinkedIn](https://www.linkedin.com/in/ifeanyiedeh)
