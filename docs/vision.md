# OpenBadger Vision  
  
## Mission  
  
OpenBadger is a free and open source, container-based, agentless asset discovery and inventory platform for internal IT teams.  
  
Its purpose is to give organizations a central, evidence-based view of devices across multiple sites by combining active scanning and passive network visibility.  
  
## Problem Statement  
  
IT teams need accurate inventory across mixed environments that include:  
  
- Windows systems  
- Linux and Unix systems  
- switches, routers, firewalls, access points, printers, UPSes, and other SNMP-capable devices  
- devices that do not respond to ping or management protocols  
  
Many existing products are expensive, closed, or broader than needed. OpenBadger focuses on the core inventory and discovery features required by most organizations without depending on endpoint agents or paid licensing.  
  
## Product Statement  
  
OpenBadger discovers, identifies, and inventories devices across multiple networks and sites using:  
  
- active discovery via ICMP, SNMP, SSH, and WinRM  
- passive discovery via packet metadata and flow exports  
- scheduled scans  
- centralized correlation of observations into assets  
  
OpenBadger is not intended to be an all-in-one IT management suite. It is intended to be a dependable, extensible inventory and discovery core.  
  
## Target Users  
  
OpenBadger is built for:  
  
- internal IT and infrastructure teams  
- network and systems administrators  
- single organizations rather than MSPs  
- mixed Windows, Linux, and network-device environments  
- small and mid-sized deployments, beginning with up to:  
  - 10 sites  
  - 5,000 devices  
  
## Core Goals  
  
1. **Agentless by default**  
   - No software agents on endpoints.  
   - Discovery occurs through network protocols and passive visibility.  
  
2. **Central inventory**  
   - Multiple sites report to a central server.  
   - Inventory is visible in one place.  
  
3. **Mixed-environment support**  
   - Windows inventory through WinRM/CIM.  
   - Linux and Unix inventory through SSH.  
   - Network and appliance inventory through SNMP.  
   - Basic reachability through ICMP.  
  
4. **Passive discovery**  
   - Detect devices that do not respond to active scans.  
   - Use packet metadata and flow exports as evidence sources.  
  
5. **Evidence-based identity**  
   - Assets are built from observations.  
   - IP address alone is never treated as a durable global identity.  
  
6. **Simple operations**  
   - Container-based deployment.  
   - One central server and one or more site-side collectors/sensors.  
   - Reasonable defaults and a small operational footprint.  
  
7. **Extensible architecture**  
   - New protocols should fit the same observation pipeline.  
   - The project should grow without major rewrites.  
  
## Design Principles  
  
### Observation-first  
Scanners and sensors produce observations. The server correlates those observations into assets.  
  
### Site-aware identity  
The same private IP range may exist in multiple sites. OpenBadger must remain correct in overlapping RFC1918 environments.  
  
### Outbound-friendly collection  
Collectors and sensors should initiate outbound connections to central whenever possible.  
  
### Start small, stay useful  
OpenBadger should ship a narrow but valuable v0.1 before adding larger features.  
  
### Secure by default  
Credentials are sensitive. Passive capture is sensitive. The system must minimize exposure and avoid collecting unnecessary payload data.  
  
### Boring operations  
Prefer straightforward, dependable components over distributed complexity.  
  
## Non-Goals  
  
OpenBadger is **not** trying to be:  
  
- a vulnerability scanner  
- a patch management platform  
- a software license management platform  
- an endpoint management product  
- a deep packet inspection platform  
- a SIEM, IDS, or NDR product  
- an MSP multi-tenant platform in v0.1  
- a full CMDB replacement in v0.1  
  
## What Success Looks Like in v0.1  
  
A successful v0.1 allows an IT team to:  
  
- deploy a central server in containers  
- deploy one collector per site or routing boundary, with one collector able to scan multiple subnets  
- optionally deploy passive sensors where mirrored traffic or flow exports are available  
- define sites, target ranges, credentials, and schedules  
- discover devices through:  
  - ICMP  
  - SNMP  
  - SSH  
  - WinRM  
  - passive packet metadata  
  - flow exports  
- view a central asset inventory with:  
  - hostname  
  - IP addresses  
  - MAC addresses  
  - vendor/model  
  - operating system  
  - first seen / last seen  
  - evidence source(s)  
  
## Long-Term Direction  
  
After the core is stable, OpenBadger can grow carefully through:  
  
- better protocol coverage  
- richer inventory detail  
- stronger asset correlation  
- improved dashboards and reporting  
- external integrations  
  
But the core promise should remain unchanged:  
  
> OpenBadger provides free, open, agentless asset discovery and inventory for real-world IT environments.  