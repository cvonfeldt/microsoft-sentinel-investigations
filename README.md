# SOC Investigation & Detection Engineering with Microsoft Sentinel and KQL

Explaining my walkthroughs and thought processes in Microsoft Sentinel SOC investigations using KQL across CrowdStrike EDR, Palo Alto firewall, Okta identity, and AWS CloudTrail logs. Includes KQL detection rules, threat hunting queries, and MITRE ATT&CK mapping.

## Parts

### [Part 1 - Exploration](Sentinel-Part-1/)
Initial data exploration across multiple enterprise security data sources using Advanced Hunting and KQL. Covers threat hunting across CrowdStrike EDR, Palo Alto firewall, Okta identity, and AWS CloudTrail logs, cross-source correlation of suspicious activity, and building a custom multi-tactic detection rule from scratch.

### [Part 2 - Microsoft Defender Threat Intelligence (MDTI) Integration](Sentinel-Part-2/)
Setting up and integrating the MDTI connector to correlate lab telemetry against Microsoft's global threat intelligence feed. Covers IOC correlation using STIX-formatted indicators, joining threat intel against firewall and cloud logs, and understanding the ThreatIntelIndicators table schema.

### [Part 3 - MITRE ATT&CK Coverage](Sentinel-Part-3/)
Analyzing detection coverage across the MITRE ATT&CK framework using the Sentinel UI. Covers identifying covered and uncovered tactics, understanding the distinction between Sentinel analytics rules and Defender XDR custom detection rules, and building an original Defense Evasion detection rule targeting process masquerading (T1036).
