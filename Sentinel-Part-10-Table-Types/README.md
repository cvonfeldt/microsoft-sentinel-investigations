# Sentinel Part 10 - Table Management & Data Lake Configuration

## Background - Analytics vs Data Lake Tiers

In this part of the lab we will learn how to view and manage table settings in the Microsoft Defender portal. We will explore the tables management screen, the difference between Analytics and Data lake tiers, and change retention settings, and then switch a table between tiers.

Some preliminary good-to-know distinctions between Analytics and Data Lakes, and general table info provided by the lab that are good to have in one place:

Data collected into Microsoft Sentinel is stored in tables. Each table can be configured independently with its own storage tier and retention period. This gives you fine-grained control over cost and performance.

Microsoft Sentinel supports two storage tiers:

| Tier | Description | Best For |
|---|---|---|
| Analytics | High-performance "hot" storage. Data is fully available for real-time analytics, hunting, alerting, workbooks, and all Sentinel features. | Active detections, threat hunting, incident investigation |
| Data lake | Low-cost "cold" storage. Data is not available for real-time analytics but can be accessed via KQL jobs, Spark jobs, and notebooks. | Compliance logging, historical trend analysis, forensics, low-touch data |

Retention Periods - within the analytics tier, there are two retention concepts:

| Setting | Range | Description |
|---|---|---|
| Analytics retention | 30 days – 2 years | How long data stays in the "hot" analytics tier for real-time querying |
| Total retention | Up to 12 years | Total data lifespan including analytics + data lake |

Free storage: Microsoft Sentinel solution tables (like CommonSecurityLog, SecurityEvent) get 90 days of analytics retention for free. XDR tables get 30 days included in the XDR license.

Cost Implications:

| Action | Cost Impact |
|---|---|
| Extending analytics retention beyond 90 days | Prorated monthly long-term retention charge |
| Extending total retention beyond analytics retention | Low-cost data lake storage charge for the additional duration |
| Moving a table from Analytics → Data lake tier | Eliminates analytics tier ingestion cost, but data loses real-time features |
| Moving a table from Data lake → Analytics tier | Re-enables real-time analytics, but incurs analytics tier ingestion cost |

Data Lake vs. Analytics tier data capabilities:

| Feature | Analytics Tier | Data Lake Tier |
|---|---|---|
| Custom detection rules | Yes | No |
| Analytics rules | Yes | No |
| Advanced Hunting | Yes | No |
| KQL jobs | Yes | Yes |
| Summary rules | Yes | Yes |
| Notebooks | Yes | Yes |
| Workbooks | Yes | No |

Built-in / Sentinel Tables:

| Table | Data Source | Tier |
|---|---|---|
| CommonSecurityLog | Palo Alto Networks firewall | Analytics |
| AWSCloudTrail | AWS CloudTrail | Analytics |
| GCPAuditLogs | Google Cloud audit logs | Analytics |
| SecurityEvent | Windows security events | Analytics |

Custom Tables:

| Table | Data Source | Tier |
|---|---|---|
| OktaV2_CL | Okta identity events | Analytics |
| MailGuard365_Threats_CL | MailGuard email threat data | Analytics |
| OfficeActivity_CL | Office 365 activity | Analytics |
| PaloAlto_ThreatSummary_KQL_CL | KQL job output (Exercise 11) | Analytics |

Understanding those distinctions, of Analytics retention being essentially hot data that is compatible with sentinel features but incurs data charges, and Data Lakes being cold data that doesn't incur charges, we can now start this part of the lab.

---
<br>

## 10.1): Tables Overview

Here we see a list of all of our tables in the workspace:

![All tables](10.1.png)

When we filter to only see data lakes, we can see we don't have any that are strictly data lake as of yet:

![Data lake filter](10.2.png)

That said, all of the analytics tables have data lake integrated - we would just need to change the total retention time to "activate" it. It would just apply once the analytics retention ends for that data.

---
<br>

## 10.2): Viewing Table Details

Clicking on specific tables, like CommonSecurityLog:

![CommonSecurityLog details](10.3.png)

We can see whether it's a data lake or an analytics table, the analytics retention time, and the total retention time. Both analytics and total are at 30 days right now but the total would be much more if data lake was utilized for this table.

---
<br>

## 10.3): Changing Analytics Retention

Here we can (with the Okta table) see how you can change the duration of the analytics retention, and the total retention auto adjusts:

![Retention settings](10.4.png)

---
<br>

## 10.4): Extending Total Retention to Utilize Data Lake

Now we extend a table's total retention time to utilize the data lake (one with high ingestion volume but that we don't really need like OfficeActivity_CL):

![Extended retention](10.5.png)

In this case, we upped the data lake retention to 2 years, so after the initial 30 days of analytics retention, the data lake rules apply. That said, after those 30 days, we could access the data from data lake and transfer it back to analytics data if we wanted to use it for hunting, alerting, workbooks, etc.

---
<br>

## 10.5): Converting a Table to Data Lake Only

We can also change a table completely to data lake if we don't need analytics retention at all. In Azure, we change the OfficeActivity_CL table to data lake completely here:

![Table converted to data lake](10.6.png)

---
<br>

## 10.6): Verifying the Data Lake Table

Going back to sentinel we can see that the table is now our only data lake table:

![Data lake table visible](10.7.png)

---
<br>

## 10.7): Switching Back to Analytics

With my subscription of Azure, you have to wait 7 days before changing data lakes back to analytics tables, but after 7 days we'd be able to change it back if we decided we needed the data for real-time processing!

---
<br>

## 10.8): KQL Jobs Workaround & Data Lake Limitations

There is actually normally a workaround for this through use of KQL jobs. KQL jobs allow us to take data from the low-cost data lake tier and write the results to the analytics tier, where it becomes available for advanced hunting queries and custom detection rules. Unfortunately on my setup apparently my region doesn't support full data lake onboarding which is where KQL jobs would normally be created and managed:

![Data lake onboarding limitation](10.8.png)

Although my tables show that data lake is integrated and I can make tables into data lakes through Azure (indicating the infrastructure is provisioned), the exploration UI was not accessible. Normally this would be accessed via Microsoft Sentinel - data lake exploration - jobs/KQL queries.

---
<br>

## 11 - KQL Jobs (Not Completed)

If we were able to get data lake fully onboarded, the next part of the lab we would have created a scheduled KQL job that queries Palo Alto firewall data from the cheaper data lake tier, aggregates it into source-destination pair summaries, and promotes the results to the analytics tier where a detection rule can query them - bridging the gap between cost-effective long term storage and real time threat detection.

---

## 12 - Data Lake vs Real-Time Detection (Not Completed)

In the part after that that builds on that, we would have compared real-time detection against data lake aggregated detection side by side - running the same port scan detection two ways: once against raw CommonSecurityLog events in near real time, and once against the pre-aggregated PaloAlto_ThreatSummary_KQL_CL table populated by the KQL job. The key tradeoff being that real-time catches threats as they happen with full event detail, while data lake detection runs on a longer delay but is cheaper and better suited for trend and anomaly  detection over extended time ranges. The exercise depended on the PaloAlto_ThreatSummary_KQL_CL table created by the KQL job in the previous exercise, which required a fully onboarded Sentinel data lake.

---

## 13 - Data Lake Notebooks (Not Completed)

In the exercise after that, we would have used Jupyter notebooks in VS Code with the Microsoft Sentinel extension to run an interactive investigation against the data lake - connecting to a spark engine to analyze Palo Alto firewall logs from CommonSecurityLog at scale. The notebook walks through a full threat investigation covering beaconing detection, DNS tunneling, data exfiltration analysis, and an attack timeline, producing interactive Plotly visualizations for each. The key advantage over portal KQL queires is that Spark processes data across distributed compute handling massive volumes, and results can be written back to the data lake or promoted to the analytics tier for follow-up KQL queries and detections. The exercise unfortunately also requires a fully onboarded Sentinel data lake, as well as a configured Spark runtime pool, neither of which were available in this lab environment.

---

## 14 - Sentinel MCP Server (Not Completed)

In part 14, we would have connected the Microsoft Sentinel MCP server to VS Code and GitHub Copilot, exposing Sentinel's data lake and Defender XDR apis as callable tools for an AI agent. It required VS Code with the sentinel extension - which I do have - but also a paid GitHub Copilot subscription, and a fully onboarded Sentinel data lake for the data exploration prompts. Part 14 though, was intended to show how natural language prompts can automatically trigger KQL queries, incident lookups, entity investigations, and lateral movement analysis - for example prompting Copilot to build a full kill chain timeline for a compromised user across CrowdStrike, Okta, AWS, and Palo Alto data sources and render it as a Mermaid diagram. You can also save your own KQL queries as custom MCP tools, turning proven hunting queries into reusable parameterized tools the whole SOC team can invoke through an AI assistant.

---

## 15 - Data Federation with ADLS Gen2 (Not Completed)

In the next exercise we would have set up data federation with Azure Data Lake Storage Gen2, which lets you query external data alongside native Sentinel tables without ingesting or duplicating it - useful for historical data too large to ingest, or business context data like HR records and asset inventories maintained by other teams. The key concept is that federated tables appear and behave like native Sentinel tables in KQL, but the data stays in the external storage. One important nuance is that if your source data includes a TimeGenerated column federation preserves the original timestamps, but without it Sentinel assigns the current query time - breaking any time-based correlation or investigation timelines.

This exercise was not completed as it requires a fully onboarded data lake, an Azure data lake Storage Gen2 account with hierarchical namespace enabled, a service principal, and an Azure key vault to store credentials - none of which were available in this lab environment yet again unfortunately.

---

## 16 - Data Transformation: Split Ingestion by Tier (Not Completed)

In part 16 we would have created a split transformation rule on the CommonSecurityLog table to route data between tiers at ingestion time - sending only denied and dropped Palo Alto firewall events to the analytics tier for real-time detction, while routing all other traffic like allow events to the cheaper Data lake tier only. This is a cost optimization pattern for high-volume tables where you don't need real-time query performance on every event, but still want everything retained for compliance and long-term investigations. The routed data lands in a new CommonSecurityLog_SPLT_CL table in the data lake, and split rules only apply to newly ingested data going forward - nothing is retroactively moved.

This was another exercise that required a fully onboarded Sentinel data lake to enable the split rule option on tables.

---

## 17 - Custom Graph: Cross-Source Attack Chain (Not Completed)

For the final part of the lab, we would have built a custom Sentinel graph correlating entities across 6 data sources - CrowdStrike, Palo alto, Okta, AWS CloudTrail, GCP Audit Logs, and MailGuard - to visualize the complete attack chain. Unlike the built-in XDR graph which only models Microsoft-centric entities, custom graphs let you define your own node and edge types from any data lake table, then query relationships using GQL (Graph Query Language). The finished graph links users, devices, IPs, cloud accounts, and email threats across all sources, letting you trace an attacker's full movement from initial email threat through endpoint compromise, identity abuse, cloud activity, and firewall traffic in a single visualization. You can then materialize it as a scheduled job so it stays current and is queryable by the whole SOC team in the Defender portal.

This part required fully onboarded data lake, a Spark compute pool, and paid GitHub Copilot for the AI authoring portion.
