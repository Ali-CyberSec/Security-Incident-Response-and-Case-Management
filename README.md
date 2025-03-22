# Security Incident Response and Case Management

## Objective
This project focuses on **detecting, investigating, and responding to security incidents** using structured **incident response frameworks** and **case management tools**. The goal is to **efficiently track, analyze, and remediate cyber threats** through a well-documented and repeatable process.

## Skills Learned
- **Incident detection and triage** based on log analysis.
- **Threat intelligence integration** to identify Indicators of Compromise (IOCs).
- **Case management and documentation** using TheHive.
- **Automated workflows** for incident response using SOAR (Shuffle).
- **Forensic analysis and log correlation** for root cause determination.
- **Remediation and mitigation techniques** to prevent future attacks.

## Tools Used
- **SIEM (Splunk, Elastic Stack, Microsoft Sentinel)** – for log aggregation and alerting.
- **TheHive** – for security case management and collaborative incident handling.
- **Shuffle (SOAR)** – for automated response playbooks.
- **Suricata/Snort** – for network-based intrusion detection.
- **MITRE ATT&CK Framework** – for mapping attack techniques.
- **Kali Linux** – for adversary simulation and pentesting.

---

## Implementation Steps

### 1. Incident Detection & Log Collection
To detect incidents, logs were collected from various sources, including **Windows Event Logs, Sysmon, IDS alerts (Suricata), and SIEM logs**.

#### Example: Detecting Failed SSH Logins in Splunk
```splunk
index=auth sourcetype=linux_secure "Failed password"
| stats count by src_ip user
| where count > 5
```

#### Configuring Suricata for Network-Based Alerts
```bash
sudo apt install suricata -y
sudo systemctl enable --now suricata
sudo suricata-update
```

#### Extracting Windows Event Logs Using PowerShell
```powershell
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4625} | Select-Object -First 10
```

### 2. Case Management in TheHive
TheHive was used to log incidents, track progress, and collaborate on investigations.

#### Steps:
- Created a new case in TheHive.
- Attached IOCs (IP addresses, hashes, domains) for tracking.
- Assigned tasks for analysis, mitigation, and reporting.
- Used Cortex analyzers to automate threat intelligence lookups.

#### Example: Automating IOC Lookups with Cortex
```bash
curl -XPOST -H "Authorization: Bearer <API_KEY>" -H "Content-Type: application/json" \
-d '{"data": "192.168.1.100", "dataType": "ip"}' \
https://cortex.example.com/api/analyzer/run
```

### 3. Automated Incident Response with Shuffle (SOAR)
To improve response times and efficiency, I used Shuffle (SOAR) to automate playbooks.

#### Automated Playbook for Blocking Malicious IPs:
```yaml
playbook:
  - trigger: "New Alert in TheHive"
  - action: "Query SIEM for related logs"
  - condition: "If malicious activity detected"
  - action: "Block IP in Firewall"
  - action: "Notify SOC Team via Slack"
```

#### Example: Manually Blocking an IP in Linux Firewall:
```bash
sudo iptables -A INPUT -s 192.168.1.100 -j DROP
```

### 4. Threat Intelligence Enrichment
To verify and correlate attack data, threat intelligence feeds were queried.

#### Checking an IP Address with VirusTotal API:
```bash
curl -X GET "https://www.virustotal.com/api/v3/ip_addresses/192.168.1.100" \
-H "x-apikey: YOUR_API_KEY"
```

#### Searching for a File Hash in Open Threat Exchange (OTX):
```bash
curl -X GET "https://otx.alienvault.com/api/v1/indicators/file/SHA256_HASH" \
-H "X-OTX-API-KEY: YOUR_API_KEY"
```

### 5. Incident Remediation & Reporting
Once an incident was fully analyzed, mitigation steps were implemented and documented.

#### Steps Taken:
- Contained the compromised system by isolating it from the network.
- Blocked malicious IPs and domains using firewall rules.
- Updated security policies to prevent similar attacks.
- Documented the incident in TheHive for future reference.
- Created a forensic timeline to track the attacker’s movements.

#### Example: Generating a Report for Incident Review
```bash
cat /var/log/suricata/fast.log | grep "ALERT" > incident_report.txt
```

## Conclusion
This project demonstrates a structured approach to incident detection, analysis, and response. By leveraging SIEM, case management, and automation, security teams can efficiently manage security incidents and improve their overall incident response maturity.
