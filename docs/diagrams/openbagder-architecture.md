# OpenBadger High-Level Architecture

```mermaid
flowchart LR
    subgraph central["Central Server"]
        server["OpenBadger Server<br/>API / UI / Scheduler / Correlator"]
        db[("PostgreSQL")]
        server --> db
    end

    subgraph siteA["Site A"]
        collectorA["Collector<br/>ICMP / SNMP / SSH / WinRM"]
        sensorA["Sensor<br/>PCAP / Flow"]
        targetsA["Reachable Subnets<br/>Servers / Clients / Network Devices"]
        visibilityA["SPAN / TAP / Flow Exporters"]

        collectorA -->|Active scans| targetsA
        targetsA -. Packet traffic .-> visibilityA
        visibilityA -->|Mirrored traffic / flow records| sensorA
    end

    subgraph siteB["Site B"]
        collectorB["Collector<br/>ICMP / SNMP / SSH / WinRM"]
        sensorB["Sensor<br/>PCAP / Flow"]
        targetsB["Reachable Subnets<br/>Servers / Clients / Network Devices"]
        visibilityB["SPAN / TAP / Flow Exporters"]

        collectorB -->|Active scans| targetsB
        targetsB -. Packet traffic .-> visibilityB
        visibilityB -->|Mirrored traffic / flow records| sensorB
    end

    collectorA -->|HTTPS/TLS<br/>Heartbeat / Job Lease / Observations| server
    sensorA -->|HTTPS/TLS<br/>Heartbeat / Passive Observations| server

    collectorB -->|HTTPS/TLS<br/>Heartbeat / Job Lease / Observations| server
    sensorB -->|HTTPS/TLS<br/>Heartbeat / Passive Observations| server