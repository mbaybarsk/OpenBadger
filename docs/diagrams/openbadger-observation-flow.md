# OpenBadger Observation and Scan Flow  
  
```mermaid  
sequenceDiagram  
    autonumber  
  
    participant Admin  
    participant Server  
    participant DB as PostgreSQL  
    participant Collector  
    participant Target  
    participant Sensor  
  
    Admin->>Server: Create site, targets, credentials, scan profiles, schedules  
    Server->>DB: Save configuration  
  
    Collector->>Server: Heartbeat + poll for eligible job  
    Server-->>Collector: Lease scan job  
  
    Collector->>Target: ICMP / SNMP / SSH / WinRM scan  
    Target-->>Collector: Responses or timeouts  
  
    Collector->>Server: Upload normalized observation batch  
    Server->>DB: Store observations  
    Server->>DB: Correlate observations into assets  
  
    Sensor->>Server: Upload passive observation batch  
    Server->>DB: Store passive sightings  
    Server->>DB: Update provisional or existing assets  
  
    Admin->>Server: View assets, evidence, jobs, node health  
```  