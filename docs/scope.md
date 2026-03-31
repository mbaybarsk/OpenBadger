# OpenBadger v0.1 Scope  
  
## Release Intent  
  
OpenBadger v0.1 is the first usable alpha release.  
  
Its job is to prove that OpenBadger can provide central, agentless, multi-site inventory using a small but valuable feature set.  
  
v0.1 is not meant to be feature-complete. It is meant to be:  
  
- installable  
- understandable  
- useful in real environments  
- a stable foundation for later versions  
  
## v0.1 Target Environment  
  
- single organization  
- up to 10 sites  
- up to 5,000 devices  
- mixed:  
  - Windows  
  - Linux/Unix  
  - network infrastructure  
  - printers/appliances/IoT where possible  
- container-based deployment  
- one collector may scan multiple subnets  
  
## In Scope  
  
## 1. Platform  
  
### 1.1 Runtime modes  
The product ships as one binary with the following modes:  
  
- `server`  
- `collector`  
- `sensor`  
- `migrate`  
  
### 1.2 Deployment  
Supported deployment for v0.1:  
  
- Docker Compose  
  
### 1.3 Storage  
Supported database for v0.1:  
  
- PostgreSQL  
  
## 2. Sites and Nodes  
  
### 2.1 Sites  
Users can create and manage sites.  
  
A site represents a logical location or network boundary for:  
  
- assets  
- collectors  
- sensors  
- target ranges  
- schedules  
  
### 2.2 Collectors  
Users can enroll collectors and see:  
  
- node name  
- site  
- capabilities  
- version  
- last heartbeat  
- health state  
  
### 2.3 Sensors  
Users can enroll sensors and see:  
  
- node name  
- site  
- capabilities  
- version  
- last heartbeat  
- health state  
  
## 3. Targeting and Scheduling  
  
### 3.1 Target ranges  
Users can define:  
  
- CIDRs  
- address ranges  
- exclusions  
  
### 3.2 Scan profiles  
Users can define protocol-specific scan profiles that include:  
  
- protocol  
- credential profile  
- timeout  
- retry count  
- concurrency  
- rate limit  
  
### 3.3 Schedules  
Users can create recurring schedules for scan profiles using cron-like expressions.  
  
### 3.4 Job tracking  
Users can view:  
  
- queued jobs  
- running jobs  
- completed jobs  
- failed jobs  
- timestamps  
- node assignment  
- error summaries  
  
## 4. Credential Handling  
  
### 4.1 Credential profiles  
Users can create credential profiles for:  
  
- SNMPv2c  
- SNMPv3  
- SSH password  
- SSH private key  
- WinRM  
  
### 4.2 Security requirements  
- credentials encrypted at rest  
- credentials not shown in plaintext after save  
- credentials scoped to the jobs that need them  
- secrets never logged  
  
## 5. Active Discovery and Inventory  
  
## 5.1 ICMP  
v0.1 includes:  
  
- liveness checks  
- RTT collection where available  
- last seen updates based on successful replies  
  
## 5.2 SNMP  
v0.1 includes:  
  
- SNMPv2c support  
- SNMPv3 support  
- system discovery:  
  - sysName  
  - sysDescr  
  - sysObjectID  
  - uptime  
- normalized vendor/model/OS fields where possible  
- interface collection  
- ARP table collection where available  
- bridge/FDB table collection where available  
  
### SNMP stretch goal for v0.1  
- LLDP/CDP enrichment if implementation time allows  
  
LLDP/CDP is useful but not release-blocking for v0.1.  
  
## 5.3 SSH  
v0.1 includes SSH-based inventory for Linux/Unix-like systems.  
  
SSH inventory should collect, where available:  
  
- hostname  
- FQDN  
- OS name  
- OS version  
- kernel version  
- architecture  
- SSH host key fingerprint  
- machine identifier when safely available  
  
SSH support in v0.1 includes:  
  
- password auth  
- key-based auth  
  
## 5.4 WinRM  
v0.1 includes WinRM-based inventory for Windows systems.  
  
WinRM inventory should collect, where available:  
  
- hostname  
- domain/workgroup  
- OS name  
- OS version  
- build number  
- manufacturer  
- model  
- serial number  
- BIOS/system UUID  
- network addresses  
  
### WinRM assumptions  
- WinRM over HTTPS is preferred  
- HTTP may be allowed only if explicitly enabled  
- inventory is collected through PowerShell/CIM queries  
- raw DCOM-based WMI is out of scope for v0.1  
  
## 6. Passive Discovery  
  
## 6.1 Packet metadata capture  
v0.1 includes passive discovery from packet metadata.  
  
The system should detect and summarize sightings based on:  
  
- Ethernet MAC addresses  
- ARP  
- IPv4/IPv6  
- ICMP/ICMPv6  
- DHCP/DHCPv6 hostname hints  
- mDNS hostname hints  
- NBNS hostname hints  
- VLAN tags where visible  
  
### Explicit limit  
v0.1 does **not** store packet payload archives.  
  
## 6.2 Flow monitoring  
v0.1 includes lightweight flow-based discovery.  
  
Release-blocking support:  
  
- IPFIX  
- NetFlow v9  
  
The flow subsystem should produce:  
  
- source/destination activity sightings  
- first seen / last seen  
- byte/packet counters where available  
  
### Explicit limit  
v0.1 flow support is for discovery evidence, not historical traffic analytics.  
  
## 7. Inventory and Correlation  
  
v0.1 includes:  
  
- normalized observations  
- asset creation from observations  
- provisional assets when only weak evidence exists  
- evidence-based merging using stronger identifiers  
- first seen / last seen per asset  
- evidence source display  
  
Asset fields shown in v0.1 should include, where available:  
  
- site  
- hostname  
- IP addresses  
- MAC addresses  
- vendor  
- model  
- operating system  
- serial number  
- first seen  
- last seen  
- evidence sources  
  
## 8. UI  
  
v0.1 includes a basic web UI with pages for:  
  
- login  
- overview/dashboard  
- sites  
- collectors  
- sensors  
- target ranges  
- credential profiles  
- scan profiles  
- schedules  
- jobs  
- assets  
- asset detail  
  
## 9. Export  
  
v0.1 includes:  
  
- CSV export of asset inventory  
  
## 10. Logging and Operations  
  
v0.1 includes:  
  
- structured logs  
- node heartbeat visibility  
- job history  
- configuration by environment variables and/or config file  
- health endpoints for server and nodes  
  
## Out of Scope  
  
The following are explicitly out of scope for v0.1:  
  
- software license management  
- patch management  
- vulnerability scanning  
- endpoint agents  
- deep packet inspection  
- packet payload archiving  
- IDS/IPS/NDR features  
- MSP multi-tenancy  
- per-customer RBAC models  
- full CMDB workflows  
- advanced reporting engine  
- historical flow analytics warehouse  
- Kubernetes-first deployment  
- plugin marketplace  
- external auth integrations beyond basic local auth  
  
## Known Constraints  
  
- passive discovery only works where traffic is visible  
- flow discovery only works where exporters are configured  
- quiet devices may still require network-table evidence or later scans  
- overlapping private IP space is expected; site-aware identity is mandatory  
- one collector can scan many subnets, but only where reachability exists  
  
## Definition of Done  
  
OpenBadger v0.1 is done when a tester can:  
  
1. deploy the server with PostgreSQL in containers  
2. enroll at least one collector and one sensor  
3. create a site and target ranges  
4. create credential profiles for SNMP, SSH, and WinRM  
5. schedule scans  
6. discover:  
   - a Linux host through SSH  
   - a Windows host through WinRM  
   - an SNMP-capable network device through SNMP  
   - a non-responsive but active device through passive packet metadata or flow evidence  
7. view those devices in the central asset inventory  
8. export the inventory to CSV  
  
## Release Quality Bar  
  
Before tagging v0.1:  
  
- core workflows must pass in a lab environment  
- no plaintext secret leakage in logs or UI  
- observation ingestion and correlation must be stable  
- documentation must cover installation and first scan  
- collector and sensor heartbeats must be visible and trustworthy  