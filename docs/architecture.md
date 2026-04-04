# OpenBadger Architecture

## 1. Overview

OpenBadger is a modular monolith with three runtime modes:

- `server`
- `collector`
- `sensor`

The system is designed for a single organization with multiple sites. It supports both active and passive discovery.

### High-level roles

- **Server**
  - Central API
  - Web UI
  - Scheduler
  - Observation ingest
  - Correlation engine
  - Inventory database

- **Collector**
  - Active scanning
  - ICMP
  - SNMP
  - SSH
  - WinRM

- **Sensor**
  - Passive packet metadata capture
  - Flow export reception
  - Local aggregation of passive sightings

## 2. Architectural Goals

The architecture must:

- support up to 10 sites and roughly 5,000 devices in v0.1
- allow one collector to scan multiple subnets
- support optional passive visibility where traffic is available
- centralize inventory and scheduling
- remain container-friendly
- be extensible without becoming microservice-heavy

## 3. Deployment Model

### 3.1 Central Server

A single central server is deployed in containers and runs:

- API
- UI
- scheduler
- correlator
- PostgreSQL

This can be deployed with Docker Compose in v0.1.

### 3.2 Site Collectors

Each site can have one or more collectors.

A collector may scan:

- multiple subnets
- multiple VLANs
- any target range reachable from its network location

Additional collectors are only required when:

- routing or ACL boundaries prevent access
- scale requires workload split
- different trust or credential boundaries exist

### 3.3 Site Sensors

Sensors are optional but recommended where passive visibility is needed.

A sensor must be placed where traffic can be seen, such as:

- SPAN/mirror port
- network TAP
- routed choke point
- device exporting flow records to the sensor

A sensor may coexist with a collector on the same host, but it remains a separate runtime role.

## 4. High-Level Topology

```text
                    +---------------------------+
                    |      OpenBadger Server    |
                    |---------------------------|
                    | API / UI                  |
                    | Scheduler                 |
                    | Correlation Engine        |
                    | PostgreSQL                |
                    +-------------+-------------+
                                  ^
                                  | outbound HTTPS/TLS
              -----------------------------------------------
              |                                             |
    +---------+---------+                         +---------+---------+
    | Site A Collector  |                         | Site A Sensor     |
    |-------------------|                         |-------------------|
    | ICMP              |                         | Packet metadata   |
    | SNMP              |                         | Flow receiver     |
    | SSH               |                         | Aggregation       |
    | WinRM             |                         +-------------------+
    +-------------------+

    +-------------------+                         +-------------------+
    | Site B Collector  |                         | Site B Sensor     |
    +-------------------+                         +-------------------+
```

## 5. Communication Model

### 5.1 Node-Initiated Connectivity

Collectors and sensors initiate outbound connections to the server.

This avoids requiring the central server to connect inbound into remote sites.

### 5.2 Enrollment

A collector or sensor is enrolled using a bootstrap token.

Enrollment returns:

- node ID
- node type
- site association
- long-lived node credential or token
- capability registration

### 5.3 Heartbeats

Collectors and sensors periodically send heartbeats including:

- node ID
- version
- health state
- capabilities
- current job count
- last successful communication

### 5.4 Job Leasing

Collectors poll the server for eligible jobs.

The server selects jobs based on:

- site
- node type
- node capabilities
- target range
- scan profile
- schedule

The collector leases a job, executes it, and reports status and observations.

### 5.5 Observation Upload

Collectors and sensors upload observations in batches.

Passive sensors should aggregate locally before upload to avoid one observation per packet or per raw flow record.

## 6. Runtime Responsibilities

### 6.1 Server

The server is responsible for:

- user-facing web UI
- API endpoints
- authentication for UI and nodes
- site management
- target range management
- credential and profile management
- schedule creation
- job generation and job tracking
- observation validation and storage
- asset correlation
- inventory views and export

### 6.2 Collector

A collector is responsible for:

- active protocol execution
- scan timeouts and retries
- protocol-specific normalization
- batching observations
- reporting job results

Supported v0.1 active capabilities:

- icmp
- snmp
- ssh
- winrm

### 6.3 Sensor

A sensor is responsible for:

- packet metadata capture
- flow export reception
- local aggregation of passive evidence
- normalization into passive observations
- upload of summarized passive observations

Supported v0.1 passive capabilities:

- pcap
- flow

## 7. Data Model

OpenBadger uses an observation-first model.

### 7.1 Core Concepts

- **Site**  
  administrative and network boundary for assets and nodes
- **Node**  
  a collector or sensor registered to a site
- **Target Range**  
  CIDR or address range to scan, with optional exclusions
- **Credential Profile**  
  a reusable protocol-specific credential set  
  examples:
  - SNMPv3 profile
  - SSH key profile
  - WinRM profile
- **Scan Profile**  
  protocol, timeout, rate limit, and credential selection rules
- **Schedule**  
  cron-like recurring execution rule
- **Job**  
  one executable unit of work assigned to a collector
- **Observation**  
  immutable normalized evidence emitted by a collector or sensor
- **Asset**  
  the correlated representation of a device
- **Sighting**  
  evidence that an asset was seen at a given time by a given source

### 7.2 Important Rule

Scanners do not directly create or mutate assets.

They emit observations.

The server correlates observations into assets.

## 8. Correlation and Asset Identity

### 8.1 Why This Matters

Different protocols see different parts of the same device.

Examples:

- SNMP may identify a switch with serial number and interfaces
- SSH may identify a Linux host by host key and hostname
- WinRM may identify a Windows host by BIOS UUID and serial number
- passive capture may only see a MAC and IP
- flow may only show IP activity

These must become one asset when evidence supports it.

### 8.2 Identifier Strength

**Strong identifiers**
- serial number
- BIOS or system UUID
- SNMP engine ID
- SSH host key fingerprint
- machine ID where trustworthy

**Medium identifiers**
- MAC address
- hostname
- SNMP sysName

**Weak identifiers**
- IP address
- DHCP hostname hint
- passive traffic-only evidence

### 8.3 Correlation Rules

- Never use IP address alone as a durable identity.
- Correlation is always site-aware.
- Strong identifier match may merge observations into one asset.
- Weak-only evidence may create a provisional asset.
- When stronger evidence appears later, provisional assets may merge.
- Conflicting strong identifiers must not merge automatically.

## 9. Scanning Model

### 9.1 Active Scanning

In v0.1, active scanning is driven by schedules and scan profiles.

A scan profile defines:

- protocol
- credentials
- timeout
- retry count
- concurrency
- rate limit
- allowed target ranges

Example profiles:

- network-snmp-default
- linux-ssh-default
- windows-winrm-default
- icmp-discovery-default

### 9.2 One Collector, Many Networks

A collector can scan multiple subnets if it has:

- IP reachability
- firewall permission
- correct credentials

No one-collector-per-subnet assumption is built into the design.

### 9.3 Passive Discovery

Passive discovery is separate from active scan reachability.

A sensor can only observe traffic that reaches its capture point or exporter.

Passive discovery sources in v0.1:

- packet metadata
- flow exports
- SNMP-derived ARP and FDB data from collectors

## 10. Protocol Support in v0.1

### 10.1 ICMP

Purpose:

- quick reachability
- liveness evidence

Initial v0.1 implementation notes:

- expand collector job targets from CIDR ranges with exclusions
- emit `icmp.alive` observations only for successful replies
- use a small sequential raw-socket IPv4 echo implementation for reliability and minimal dependencies

### 10.2 SNMP

Purpose:

- network device inventory
- interfaces
- ARP
- bridge/FDB data

Initial support:

- SNMPv2c
- SNMPv3

### 10.3 SSH

Purpose:

- Linux/Unix inventory
- host key fingerprint
- OS and kernel details

### 10.4 WinRM

Purpose:

- Windows inventory via PowerShell/CIM
- host identity and OS details

OpenBadger uses WinRM in v0.1 rather than raw DCOM-based WMI.

### 10.5 Packet Metadata Capture

Purpose:

- detect devices that do not answer active probes
- identify MAC/IP sightings
- gather hostname hints from DHCP, mDNS, and NBNS
- capture ARP visibility

### 10.6 Flow Receiver

Purpose:

- detect IP activity from otherwise non-responsive devices
- provide first seen / last seen evidence

v0.1 should target:

- IPFIX
- NetFlow v9

The flow subsystem should be abstract enough to add sFlow later.

## 11. Observation Pipeline

### 11.1 Active Observation Flow

- Scheduler creates a job.
- Eligible collector leases the job.
- Collector performs protocol action.
- Collector normalizes results into observations.
- Collector sends observations in batches.
- Server validates and stores observations.
- Correlation engine updates assets and sightings.

### 11.2 Passive Observation Flow

- Sensor captures packet metadata or receives flow exports.
- Sensor extracts identifying metadata only.
- Sensor aggregates locally over short time windows.
- Sensor emits summarized passive observations.
- Server stores and correlates those observations.

### 11.3 Local Aggregation Requirement

Passive components must aggregate before upload.

Do not send:

- one observation per packet
- one observation per raw flow record

Instead send periodic summaries such as:

- MAC/IP sighting from 12:00:00 to 12:01:00
- flow activity for IP X during window Y

## 12. Security Model

### 12.1 Transport Security

- All node-to-server traffic uses HTTPS/TLS.
- Node enrollment uses bootstrap tokens.
- Nodes receive scoped long-lived credentials after enrollment.

### 12.2 Credential Handling

- Credentials are encrypted at rest on the server.
- Collectors receive only the credentials required for the leased job.
- Collectors should avoid persisting secrets locally unless explicitly configured.

### 12.3 Least Privilege

- SSH commands should not require root for basic inventory.
- WinRM should use the least privilege necessary.
- Packet capture should collect metadata only, not payload archives.

### 12.4 Sensitive Data Minimization

OpenBadger does not store:

- packet payload archives
- private keys in raw observation bodies
- plaintext credentials in logs
- unnecessary copies of protocol responses

## 13. Persistence

PostgreSQL is the system of record for v0.1.

It stores:

- sites
- nodes
- target ranges
- credential profiles
- scan profiles
- schedules
- jobs
- observations
- assets
- identifiers
- addresses
- sightings

Observations may be stored as structured columns plus JSONB payload for protocol-specific facts.

## 14. UI and API

The v0.1 UI should provide:

- sites
- collectors and sensors
- target ranges
- credential profiles
- scan profiles
- schedules
- jobs
- assets
- asset detail
- CSV export

The API should support:

- node enrollment
- heartbeat
- job lease/update
- observation batch ingest
- CRUD for core admin objects

## 15. Deployment and Runtime Constraints

### 15.1 Containers

All roles are containerized.

### 15.2 Collector privileges

Collectors may require:

- CAP_NET_RAW for ICMP

The current ICMP runner uses raw IPv4 ICMP echo sockets through the Go standard library.

On Linux this typically means the collector process must run as root or have `CAP_NET_RAW`.

For container deployments, add `NET_RAW` to the collector container capabilities.

Without that privilege, ICMP jobs will fail with a permission error when opening the raw socket.

### 15.3 Sensor privileges

Sensors may require:

- host networking
- CAP_NET_RAW
- CAP_NET_ADMIN
- access to a mirrored or monitored interface

### 15.4 First deployment target

Docker Compose is the first deployment target. Kubernetes is explicitly not required for v0.1.

## 16. Scale Assumptions for v0.1

The design target for v0.1 is:

- 1 organization
- up to 10 sites
- up to 5,000 devices
- multiple subnets per collector
- low-to-moderate passive visibility volume with local aggregation

This scale does not require distributed messaging systems in v0.1.

## 17. Extensibility

OpenBadger should remain extensible by adding new observation producers.

Examples of future additions:

- new protocol scanners
- DHCP or DNS log ingestion
- LLDP/CDP enrichment
- stronger user auth and RBAC
- new export formats
- integration APIs

The key rule is unchanged:

New capabilities should emit observations into the same correlation pipeline rather than invent their own inventory model.
