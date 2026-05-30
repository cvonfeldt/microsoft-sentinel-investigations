# Sentinel Parts 11 through 17 Explanations - Missing Environment Utilities

### As we saw at the end of part 10, we are unfortunaly unable to get datalake fully onboarded due to my region:
![DLmissing](screenshots/10.8.png)
<br>

### That said, this portion of the lab will be dedicated to going through both what we would've done for parts 11 through 17, summaries of the concepts in each part, and what utilities would've been needed (many parts required more than just full datalake).
---
<br>

## Part 11: KQL Jobs 

### If we were able to get data lake fully onboarded, the next part of the lab we would have created a scheduled KQL job that queries Palo Alto firewall data from the cheaper data lake tier, aggregates it into source-destination pair summaries, and promotes the results to the analytics tier where a detection rule can query them - bridging the gap between cost-effective long term storage and real time threat detection.

---
<br>

## Part 12: Data Lake vs Real-Time Detection 

### In the part after that that builds on that, we would have compared real-time detection against data lake aggregated detection side by side - running the same port scan detection two ways: once against raw CommonSecurityLog events in near real time, and once against the pre-aggregated PaloAlto_ThreatSummary_KQL_CL table populated by the KQL job. The key tradeoff being that real-time catches threats as they happen with full event detail, while data lake detection runs on a longer delay but is cheaper and better suited for trend and anomaly  detection over extended time ranges. The exercise depended on the PaloAlto_ThreatSummary_KQL_CL table created by the KQL job in the previous exercise, which required a fully onboarded Sentinel data lake.

---
<br>

## Part 13: Data Lake Notebooks 

### In the exercise after that, we would have used Jupyter notebooks in VS Code with the Microsoft Sentinel extension to run an interactive investigation against the data lake - connecting to a spark engine to analyze Palo Alto firewall logs from CommonSecurityLog at scale. The notebook walks through a full threat investigation covering beaconing detection, DNS tunneling, data exfiltration analysis, and an attack timeline, producing interactive Plotly visualizations for each. The key advantage over portal KQL queires is that Spark processes data across distributed compute handling massive volumes, and results can be written back to the data lake or promoted to the analytics tier for follow-up KQL queries and detections. The exercise unfortunately also requires a fully onboarded Sentinel data lake, as well as a configured Spark runtime pool, neither of which were available in this lab environment.

---
<br>

## Part 14: Sentinel MCP Server 

### In part 14, we would have connected the Microsoft Sentinel MCP server to VS Code and GitHub Copilot, exposing Sentinel's data lake and Defender XDR apis as callable tools for an AI agent. It required VS Code with the sentinel extension - which I do have - but also a paid GitHub Copilot subscription, and a fully onboarded Sentinel data lake for the data exploration prompts. Part 14 though, was intended to show how natural language prompts can automatically trigger KQL queries, incident lookups, entity investigations, and lateral movement analysis - for example prompting Copilot to build a full kill chain timeline for a compromised user across CrowdStrike, Okta, AWS, and Palo Alto data sources and render it as a Mermaid diagram. You can also save your own KQL queries as custom MCP tools, turning proven hunting queries into reusable parameterized tools the whole SOC team can invoke through an AI assistant.

---
<br>

## Part 15: Data Federation with ADLS Gen2 

### In the next exercise we would have set up data federation with Azure Data Lake Storage Gen2, which lets you query external data alongside native Sentinel tables without ingesting or duplicating it - useful for historical data too large to ingest, or business context data like HR records and asset inventories maintained by other teams. The key concept is that federated tables appear and behave like native Sentinel tables in KQL, but the data stays in the external storage. One important nuance is that if your source data includes a TimeGenerated column federation preserves the original timestamps, but without it Sentinel assigns the current query time - breaking any time-based correlation or investigation timelines.

### This exercise was not completed as it requires a fully onboarded data lake, an Azure data lake Storage Gen2 account with hierarchical namespace enabled, a service principal, and an Azure key vault to store credentials - none of which were available in this lab environment yet again unfortunately.

---
<br>

## Part 16: Data Transformation - Split Ingestion by Tier 

### In part 16 we would have created a split transformation rule on the CommonSecurityLog table to route data between tiers at ingestion time - sending only denied and dropped Palo Alto firewall events to the analytics tier for real-time detction, while routing all other traffic like allow events to the cheaper Data lake tier only. This is a cost optimization pattern for high-volume tables where you don't need real-time query performance on every event, but still want everything retained for compliance and long-term investigations. The routed data lands in a new CommonSecurityLog_SPLT_CL table in the data lake, and split rules only apply to newly ingested data going forward - nothing is retroactively moved.

### This was another exercise that required a fully onboarded Sentinel data lake to enable the split rule option on tables.

---
<br>

## Part 17: Custom Graph - Cross-Source Attack Chain

### For the final part of the lab, we would have built a custom Sentinel graph correlating entities across 6 data sources - CrowdStrike, Palo alto, Okta, AWS CloudTrail, GCP Audit Logs, and MailGuard - to visualize the complete attack chain. Unlike the built-in XDR graph which only models Microsoft-centric entities, custom graphs let you define your own node and edge types from any data lake table, then query relationships using GQL (Graph Query Language). The finished graph links users, devices, IPs, cloud accounts, and email threats across all sources, letting you trace an attacker's full movement from initial email threat through endpoint compromise, identity abuse, cloud activity, and firewall traffic in a single visualization. You can then materialize it as a scheduled job so it stays current and is queryable by the whole SOC team in the Defender portal.

##### This part required fully onboarded data lake, a Spark compute pool, and paid GitHub Copilot for the AI authoring portion.
