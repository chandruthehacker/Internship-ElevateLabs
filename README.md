# 30‑Day Cybersecurity Internship – Hands‑On Log

A day‑by‑day record of the practical tasks I completed during my 30‑day internship.  
Each entry links to the GitHub repo that holds scripts, notes, and evidence.

---

## Day‑by‑Day Work

- **Day 1 – Port Scanning**  
  Repo ➡️ [ElevateLabs-Day1-PortScan](https://github.com/chandruthehacker/ElevateLabs-Day1-PortScan)  
  Installed **Nmap**, scanned the local /24 network with a TCP SYN scan, logged open ports, captured packets with **Wireshark**, and noted security risks.

- **Day 2 – Phishing Email Detection**  
  Repo ➡️ [ElevateLabs-Day2-Phishing-Detection](https://github.com/chandruthehacker/ElevateLabs-Day2-Phishing-Detection)  
  Dissected a sample phishing email—checked headers, spoofed sender, suspicious links, urgent language, and summarised red‑flag traits.

- **Day 3 – Vulnerability Scan**  
  Repo ➡️ [ElevateLabs-Day3-VulnScan](https://github.com/chandruthehacker/ElevateLabs-Day3-VulnScan)  
  Ran **Nessus Essentials** against my PC, reviewed critical findings, researched mitigations, and captured report screenshots.

- **Day 4 – Host Firewall Hardening**  
  Repo ➡️ [ElevateLabs-Day4-Firewall-Hardening](https://github.com/chandruthehacker/ElevateLabs-Day4-Firewall-Hardening)  
  Configured Windows Firewall/**UFW** rules, blocked Telnet (23), allowed SSH (22), tested connectivity, and documented commands.

- **Day 5 – Packet Capture & Filtering**  
  Repo ➡️ [ElevateLabs-Day5-Pcap-Analysis](https://github.com/chandruthehacker/ElevateLabs-Day5-Pcap-Analysis)  
  Captured traffic with **tcpdump**, applied Wireshark filters, isolated suspicious TCP streams, and saved annotated PCAPs.

- **Day 6 – Splunk Setup & Log Ingest**  
  Repo ➡️ [ElevateLabs-Day6-Splunk-Setup](https://github.com/chandruthehacker/ElevateLabs-Day6-Splunk-Setup)  
  Installed Splunk Free, forwarded Windows Event Logs, and verified data onboarding.

- **Day 7 – SPL Query & Dashboard**  
  Repo ➡️ [ElevateLabs-Day7-SPL-Dashboard](https://github.com/chandruthehacker/ElevateLabs-Day7-SPL-Dashboard)  
  Wrote basic SPL queries, created a security‑events dashboard, and shared screenshots.

- **Day 8 – Brute‑Force Alert Rule**  
  Repo ➡️ [ElevateLabs-Day8-BruteForce-Alert](https://github.com/chandruthehacker/ElevateLabs-Day8-BruteForce-Alert)  
  Built a Splunk alert to detect multiple failed logins, tested with simulated attempts, and tuned thresholds.

- **Day 9 – Windows Hardening Baseline**  
  Repo ➡️ [ElevateLabs-Day9-Windows-Hardening](https://github.com/chandruthehacker/ElevateLabs-Day9-Windows-Hardening)  
  Disabled SMBv1, enforced strong password policy, and documented before/after benchmarks.

- **Day 10 – Linux Syslog Analysis**  
  Repo ➡️ [ElevateLabs-Day10-Linux-Syslog](https://github.com/chandruthehacker/ElevateLabs-Day10-Linux-Syslog)  
  Parsed `/var/log/auth.log` for sudo misuse and SSH anomalies with grep/AWK.

- **Day 11 – Advanced Wireshark Filters**  
  Repo ➡️ [ElevateLabs-Day11-Advanced-Wireshark](https://github.com/chandruthehacker/ElevateLabs-Day11-Advanced-Wireshark)  
  Crafted display filters for SSL handshakes, DNS tunnels, and exfil patterns.

- **Day 12 – Password Cracking Lab**  
  Repo ➡️ [ElevateLabs-Day12-Password-Cracking](https://github.com/chandruthehacker/ElevateLabs-Day12-Password-Cracking)  
  Used **John the Ripper** to crack weak NTLM hashes from a sample SAM file and documented prevention tips.

- **Day 13 – Patch Management Simulation**  
  Repo ➡️ [ElevateLabs-Day13-Patch-Management](https://github.com/chandruthehacker/ElevateLabs-Day13-Patch-Management)  
  Emulated a WSUS cycle: identified outdated software, applied patches, and logged change control.

- **Day 14 – Threat‑Intel Feed Integration**  
  Repo ➡️ [ElevateLabs-Day14-Threat-Intel](https://github.com/chandruthehacker/ElevateLabs-Day14-Threat-Intel)  
  Pulled AbuseIPDB feed into Splunk, enriched logs with IP reputation, and created a TI dashboard.

- **Day 15 – Honeypot Deployment**  
  Repo ➡️ [ElevateLabs-Day15-Honeypot](https://github.com/chandruthehacker/ElevateLabs-Day15-Honeypot)  
  Deployed **Cowrie** SSH honeypot on a VM, captured attacker fingerprints, and visualised hits.

- **Day 16 – IDS Setup (Snort)**  
  Repo ➡️ [ElevateLabs-Day16-IDS-Snort](https://github.com/chandruthehacker/ElevateLabs-Day16-IDS-Snort)  
  Installed Snort, tuned community rules, triggered test exploits, and reviewed alerts.

- **Day 17 – Malware Analysis Primer**  
  Repo ➡️ [ElevateLabs-Day17-Malware-Analysis](https://github.com/chandruthehacker/ElevateLabs-Day17-Malware-Analysis)  
  Performed static analysis (strings, hash), detonated in a sandbox, and logged IOCs.

- **Day 18 – Event Correlation Exercise**  
  Repo ➡️ [ElevateLabs-Day18-Event-Correlation](https://github.com/chandruthehacker/ElevateLabs-Day18-Event-Correlation)  
  Correlated firewall, endpoint, and AD logs to trace a lateral‑movement scenario in Splunk.

- **Day 19 – Endpoint Monitoring with OSQuery**  
  Repo ➡️ [ElevateLabs-Day19-OSQuery](https://github.com/chandruthehacker/ElevateLabs-Day19-OSQuery)  
  Deployed OSQuery, wrote scheduled queries for autoruns, USB insertions, and shipped results to ELK.

- **Day 20 – Incident‑Response Playbook**  
  Repo ➡️ [ElevateLabs-Day20-IR-Playbook](https://github.com/chandruthehacker/ElevateLabs-Day20-IR-Playbook)  
  Authored a step‑by‑step playbook for phishing incidents, including containment, eradication, and lessons learned.

- **Day 21 – Phishing Simulation & Awareness**  
  Repo ➡️ [ElevateLabs-Day21-Phishing-Sim](https://github.com/chandruthehacker/ElevateLabs-Day21-Phishing-Sim)  
  Ran **GoPhish** campaign, measured click‑through rate, and presented user‑awareness metrics.

- **Day 22 – Disk Forensics (Autopsy)**  
  Repo ➡️ [ElevateLabs-Day22-Disk-Forensics](https://github.com/chandruthehacker/ElevateLabs-Day22-Disk-Forensics)  
  Imaged a VM disk, carved deleted files, and recovered browser artefacts.

- **Day 23 – YARA Rule Writing**  
  Repo ➡️ [ElevateLabs-Day23-YARA-Rules](https://github.com/chandruthehacker/ElevateLabs-Day23-YARA-Rules)  
  Created custom YARA signatures for a malicious PDF and verified hits in VirusTotal.

- **Day 24 – Log Forwarding with Beats**  
  Repo ➡️ [ElevateLabs-Day24-Beats-Forwarder](https://github.com/chandruthehacker/ElevateLabs-Day24-Beats-Forwarder)  
  Configured **FileBeat** and **Winlogbeat** to ship logs into the ELK stack, validated dashboards.

- **Day 25 – SOC Shift‑Report Automation**  
  Repo ➡️ [ElevateLabs-Day25-SOC-Report](https://github.com/chandruthehacker/ElevateLabs-Day25-SOC-Report)  
  Wrote a Python script to pull critical alerts and email a PDF shift‑summary automatically.

- **Day 26 – MITRE ATT&CK Mapping**  
  Repo ➡️ [ElevateLabs-Day26-ATTACK-Mapping](https://github.com/chandruthehacker/ElevateLabs-Day26-ATTACK-Mapping)  
  Mapped previous alerts to ATT&CK tactics/techniques and visualised coverage gaps.

- **Day 27 – Cloud Security (GuardDuty)**  
  Repo ➡️ [ElevateLabs-Day27-Cloud-GuardDuty](https://github.com/chandruthehacker/ElevateLabs-Day27-Cloud-GuardDuty)  
  Enabled AWS GuardDuty, generated test findings, and triaged alerts.

- **Day 28 – Container Security Scan**  
  Repo ➡️ [ElevateLabs-Day28-Container-Scan](https://github.com/chandruthehacker/ElevateLabs-Day28-Container-Scan)  
  Scanned a Docker image with **Trivy**, fixed high‑severity CVEs, and pushed a hardened image.

- **Day 29 – SOAR‑Lite Automation Script**  
  Repo ➡️ [ElevateLabs-Day29-SOAR-Lite](https://github.com/chandruthehacker/ElevateLabs-Day29-SOAR-Lite)  
  Built a Python script to auto‑block malicious IPs via firewall API when Splunk raises a high‑fidelity alert.

- **Day 30 – Final Presentation & Wrap‑Up**  
  Repo ➡️ [ElevateLabs-Day30-Final-Report](https://github.com/chandruthehacker/ElevateLabs-Day30-Final-Report)  
  Consolidated findings, dashboards, and lessons learned into a slide deck and updated this README.

---

### 📌 How to Use

1. Clone any day’s repo to explore code, scripts, and evidence.  
2. Follow the README inside each repo for reproduction steps.  
3. PRs and feedback are welcome!

---

*© 2025 Chandraprakash C – chandruthehacker*
