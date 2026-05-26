Part 4 - Real World SOC Attack Simulation & MITRE Mapping

4.1): For this portion of the lab, I’m going to manually detect and map out the phases of the attack to their specific MITRE tactics. Since the MITRE grid didn’t output as intended, we weren’t able to simply map out the attack according to it. The lab deployed rules take us through the attack phases one by one (with their names), but I want to try to trace the attack phases without it and simulate a real-world SOC investigation as if we don’t have the perfectly-made rules already. 

We will use the first deployed rule for the first stage only to give us a starting point.

Here we see the first stage of the attack: A phishing email that bypassed MailGuard SEG from IP: “198.51.100.42” with the payload: “report.exe”.
(a1.0.png)
(a1.2.png)

We see here that the MITRE tactics involved are T1566.001 (spearfishing attachment) and T1566.002 (spearfishing link). 

This valuable info, especially the payload file, as well as the below findings will be key to tracing the compromise and its next developments:
(a1.1.png)

Here we have the email it was delivered to: “mirage@pkwork.onmicrosoft.com”, the recipient user: “mirage”, and the time of the email: 7:08:40 AM on May 22nd. 

This is crucial because we now know when to reference time-wise for next stages of the compromise, as well as the email/user on this device (device that will presumably be compromised).

Clicking into the query that actually fired the alert, we see some more specific details regarding the email, including the SPF, DKIM, and DMARC results, the email subject, and the sender’s address/domain: 
(a1.7.png)
(a1.8.png)

We see that SPF, DKIM, and DMARC all fail, which makes me wonder why MailGuard let the email through. We also see that the sender’s domain “pkwork-hr.com”  is spoofed, as the real one would have “onmicrosoft.com” in it. 


4.2): Now to find the next stage of the attack, we know that we are working with an endpoint device that was sent a malicious payload, so we know we’ll need to query a CrowdStrike table (the EDR vendor in this environment). Since we have worked with the CrowdStrikeAlert table so far, we will query it to see if its columns/data includes a user so we can correlate with the hostname and the rest of the attack: 
(a2.1.png)

We can see here that CrowdStrikeAlerts contains the columns “UserID” and “UserName,” which is seem like what we’re looking for but let’s see how they’re formatted:
(a2.11.png)

As we can see, even though they’re columns in the table, they’re blank in every entry. The same goes for the “SourceIps” and “FileName” columns. In fact, all of the following searches returned no results: 
CrowdStrikeAlerts
| search "report.exe"


CrowdStrikeAlerts
| search "mirage*"


CrowdStrikeAlerts
| search "198.51.100.42"


CrowdStrikeAlerts
| search "198.51.100.42"


CrowdStrikeAlerts
| search "*pkwork-hr.com"




We will need to take a different approach: Since we’ve ruled out any query working with the known payload filename, sender IP, sender email, and destination user/email. Let’s inspect deeper regarding the type of payload: We know the malicious file is a .exe file that will be run, and looking at the “Names” column of the table, we see “User Execution: Malicious File” and “Malicious PowerShell Execution”:
(2.14.png)

One of these will undoubtedly be the “Name” of the alert that fires when the user clicks on the phishing link and report.exe runs.

On top of that, we know that the time of the email was 7:08:40 AM on May 22nd, and that there is a “TimeGenerated” column. Also there is a “Status” column that tells whether the alert is a false or true positive. Let’s put all of it into a query and see what returns: 

(a2.15.png)
(a2.16.png)

Looks like that did it! We can see the “Name” of the alerts is “malicious powershell execution”, and the attacker’s objective is “gain access,” which lines up perfectly with what presumably occurred in the initial compromise of running report.exe. This maps cleanly to MITRE tactic T1204.002: User Execution: Malicious File. 

We also get the golden nuggets of what we need to continue our trace: Mirage user’s infected host machine mentioned in AgentId: “win11a”, and that the payload was executed at 7:10:34 AM on May 22, 2026!


4.3): Now that we know the device infected and the time of infection, we can narrow down our CrowdStrikeAlert query to analyze the malicious activities that followed: 
(a3.0.png)

So scrolling through the 14 results from the query of true positives on the infected machine, we see they all have the same exact time generated, so we won’t be able to simply chronologically map the attack sequence.

On top of that, we unfortunately don’t see anything relating to commandline or child/parent process IDs, so we can’t find what the report.exe spawned exactly. We do see credential harvesting from LSASS though on the infected machine!:
(sub.png)

This is the next stage in our attack and these alerts maps to MITRE tactic 1003.001: “Extracting credentials from the Local Security Authority Subsystem Service (LSASS) process on Windows”

These are both true_positives and will very likely be a major attack vector going forward to keep an eye on.


4.4): Looking over the CrowdStrike logs, I’m realizing that I was treating the “AgentID” column as the sourceIP, thinking that it would have to be win11a to infect the other hosts, when in reality AgentID is simply the endpoint device associated with the alert. This makes a lot more sense considering CrowdStrike is our EDR tool and not one that monitors network/transmission. With that in mind…

We see something glaring when searching other endpoint devices after the initial compromise: There appears to be lateral movement:
(ae1.png)

Of the given agentIDs/DisplayNames: 
(ae2.png)

We can see our lateral movement alert to win11d via smb! This was almost certainly achieved using the credentials harvested prior. This specifically maps to (T1021.002): “Adversaries may use Valid Accounts to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user”

4.5): Removing the win11a filter, we now that we know at least 7 machines have been infected: 
(new.png)
(new1.png)

Win11a, win11b, win11c, win11d, srvfile, srvdc, itws, and devws01.

We want to check if palo alto detected any more potential movement between these hosts and/or outgoing to an attack beacon.

Just to get a refresher on what columns we can utilize in Palo Alto, lets run a getschema first:
(3.2.png)

Analyzing TimeGenerated, and SourceHostName, let’s see what hosts were involved in network activity as the source: 
(a4.1.png)

We get only one source host: win11a, and we also get its IP: 10.0.1.50

Now let’s try to identify traffic to “srvfile” - it clearly seems like a file server based on the name, so we know that if the movement shows up on Palo Alto, it would have the destination port 20, 21 (both FTP), 22 (SFTP), 139 (NetBIOS) or 445 (SMB), so let’s query that:

(a4.2.png)

We see that all of the logs with ports having to do with file transfer have the destinationIP: 
10.0.1.200, so we can assume that is our fileserver IP address. There is something separate here that we notice that raises red flags: These 4 port connections all getting blocked/dropped seems indicative of a port scan:
(a.4.3.png)

Let’s remove the file-only port filter to see all ports that dropped connections:
(a4.4.png)

We can see all of these very commonly used ports’ connections being dropped at the same time, which has to be an automated scan. So we have our next documented stage of the attack: MITRE ATT&CK 1046: Network Service Discovery. This differs from 1595: Active Scanning, as 1046 “refers to Network Service Discovery (Discovery) used to map internal services once access has been established,” while 1595 is “scanning to find a way in” according to MITRE.org.

Whether this network scanning occurred before or after the lateral movement is difficult to say given we don’t have any time difference or process relationships. It’s equally as likely that report.exe executed a script automated these operations to occur simultaneously. 

4.6): Pivoting back to potential lateral/outgoing beacon connection, it seems like we have gleaned about as much as we can out of the palo alto logs in regards to the movement from win11a to itws and srvfile. Unfortunately it also seems like we can’t get ThreatIntelIndicators logs from the time of the attack, as I connected to MDTI after the attack (had to make a new account):
(1.png)

The natural next step to identifying the aftermath of the credential harvesting after physical network activity, would be Okta MFA logs to see if the harvested credentials were used in Okta logins.

First we will view the table at the time of the attack:
(2.png)

We immediately see many red flags right from the get go. All 36 Okta events fired at the same exact time during the attack, which tells us that these were all automated. We are seeing extremely concerning EventMessages such as Grant user super admin role, Reset all MFA factors for user CEO PKWork, Deactivate SMS factor for user Priya Sharma, Enroll new TOTP factor for attacker-controlled device, etc.

(3.png) 

We see 6 users accounts successfully compromised - clearly of varying levels of roles/privileges (super admin role, CEO credentials, etc.) - and when checking the location of the logins:
(4.png)
(5.png)

We see they’re from all over the place - and again, at the same time - so obviously automated… Even logins to the same account are from different areas/stats completely which obviously indicates impossible travel (if we didn’t already know the accounts were compromised). 

We can conclude that the privilege escalation indeed came from credential harvesting of multiple accounts and bypassing of Okta MFA security measures. This would map to MITRE tactic 1556.006: “Disabling or weakening MFA policies to bypass secondary verification.” 

4.7): I know that attackers love to create persistence early before making too much noise on the victim network. At this point with credentials harvested, lateral movements, and Okta MFA manipulation, you’d certainly think they would’ve created a backdoor by now. Shifting our focus to only the nature of the alerts, (but still making sure the alerts are after the initial compromise) we can query our Palo Alto firewall: 
(a3.1.png)

Looking at the objectives of the alerts, we see “Maintain Presence,” which is the persistence we are looking for. In the alerts with “Maintain Presence”, we see a C2 beacon detection as well as a C2 Network connection. Knowing this, we know we can now correlate results with our Palo Alto firewall logs since a connection is being made.

We know for the connection to the C2 beacon to be made, a DNS request must first be made.

We will use DestinationPort (53 for DNS), TimeGenerated, SourceHostName:
(a3.4.png)

We see that of the DNS requests from the originally infected host, the only resolved DNS IP address that was external was DestinationTranslatedAddress:192.0.2.100, and that in “DeviceCustomString1” it says command-and-control (C2), so we have our C2 beacon IP! We also see our infected machine’s IP is SourceIP :10.0.1.50. 

