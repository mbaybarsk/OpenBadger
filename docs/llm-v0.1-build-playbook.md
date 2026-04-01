# OpenBadger v0.1 LLM Build Playbook  
  
## Purpose  
  
This file is a practical, step-by-step build guide for OpenBadger v0.1.  
  
It is written for two audiences at the same time:  
  
1. **You**, as an IT professional who may not want deep software-engineering detail at every step  
2. **LLMs** such as Cline / GPT / Claude, which can use the prompts in this file to generate the code  
  
This is not a single giant prompt.    
It is a sequence of **small, controlled build requests**.  
  
## How to use this file  
  
- Do **one step at a time**  
- Do **not** ask the LLM to do multiple numbered steps at once  
- Do not move to the next step until:  
  - the code builds  
  - the tests pass  
  - the manual check works  
  
## Very short glossary  
  
- **Server** = the central control system  
- **Collector** = the active scanner at a site  
- **Sensor** = the passive listener at a site  
- **Job** = a work order sent to a collector  
- **Observation** = a fact/evidence record produced by a scan  
- **Asset** = the merged inventory record built from observations  
  
## Dependency policy  
  
Start small. Only add dependencies when the step truly needs them.  
  
### Foundation dependencies  
  
Use these early:  
  
- `github.com/jackc/pgx/v5`  
- `github.com/caarlos0/env/v11`  
- `github.com/google/uuid`  
- a migration tool such as `github.com/pressly/goose/v3`  
  
### Later dependencies  
  
Add only when needed:  
  
- ICMP: `golang.org/x/net`  
- Scheduling: `github.com/robfig/cron/v3`  
- SNMP: `github.com/gosnmp/gosnmp`  
- SSH: `golang.org/x/crypto/ssh`  
- WinRM: `github.com/masterzen/winrm` (or another library only if justified)  
- Passive PCAP: `github.com/google/gopacket`  
- Flow: choose a parser library only when you reach the flow step  
  
### Do not add these in v0.1 unless there is a very strong reason  
  
- Gin  
- Echo  
- Cobra  
- GORM  
- Viper  
- React/Vue frontend frameworks  
- message brokers  
  
Keep it simple.  
  
---  
  
# Global prompt to prepend to every LLM request  
  
Copy this block and place it **before** the step-specific prompt.  
  
```text  
You are helping build OpenBadger v0.1 in this repository.  
  
Follow these design constraints:  
- Development environment: Windows 10/VS Code
- Language: Go  
- Architecture: modular monolith  
- One binary with modes: server, collector, sensor, migrate  
- Use stdlib where possible  
- Use net/http, html/template, log/slog unless there is a strong reason not to  
- Prefer pgx for PostgreSQL  
- Minimize dependencies  
- Do not add large frameworks unless explicitly requested  
- Follow the existing docs:  
  - docs/vision.md  
  - docs/architecture.md  
  - docs/v0.1-scope.md  
  - docs/observation-schema.md  
- Make the smallest clean change needed for this step  
- Do not implement future steps unless they are required to complete this one  
- If a schema change is needed, add a SQL migration  
- Add tests for the code you write  
- For integration tests that need external systems, make them skip cleanly unless env vars are set  
- At the end, provide:  
  1. a summary of what changed  
  2. files changed  
  3. how to run tests  
  4. how to manually verify the step  
```  
  
---  
  
# STEP 1 — Create the basic executable skeleton  
  
## What this means in IT terms  
  
This is the chassis of the product.    
You are not building scanning yet. You are building the basic executable so the project can run in different modes.  
  
## Ask the LLM  
  
```text  
Implement the OpenBadger executable skeleton.  
  
Requirements:  
- Create one Go binary in cmd/openbadger/main.go  
- Support these subcommands or modes:  
  - server  
  - collector  
  - sensor  
  - migrate  
- Use simple stdlib argument parsing; do not add Cobra  
- Create minimal package structure for:  
  - internal/server  
  - internal/collector  
  - internal/sensor  
  - internal/config  
  - internal/version  
- Each mode should start, log a startup message, and exit cleanly on context cancellation  
- Add a Makefile with at least:  
  - build  
  - test  
  - run-server  
  - run-collector  
  - run-sensor  
- Keep the implementation intentionally small; no business logic yet  
- Add any small unit tests that make sense for argument parsing or startup helpers  
```  
  
## Tests to request  
  
```text  
Add tests for any helper used to select or parse runtime mode. Keep tests small and table-driven.  
```  
  
## What to run  
  
```bash  
make build  
make test  
go run ./cmd/openbadger server  
go run ./cmd/openbadger collector  
go run ./cmd/openbadger sensor  
go run ./cmd/openbadger migrate  
```  
  
## Success looks like  
  
- The binary builds  
- Each mode starts without crashing  
- Logs are visible  
- The codebase now has a recognizable shape  
  
---  
  
# STEP 2 — Add config, logging, and health endpoints  
  
## What this means in IT terms  
  
You are teaching the tool how to read settings and report basic health.    
This is like giving a network appliance its config knobs and a “status OK” page.  
  
## Ask the LLM  
  
```text  
Add configuration loading, structured logging, and basic health endpoints.  
  
Requirements:  
- Add config loading from environment variables  
- Use caarlos0/env unless there is a strong reason otherwise  
- Define config structs for server, collector, sensor, and database settings  
- Use log/slog for structured logging  
- In server mode, expose:  
  - GET /healthz  
  - GET /readyz  
- Return JSON from health endpoints  
- Keep config and logging code simple and testable  
- Update the Makefile if needed  
```  
  
## Tests to request  
  
```text  
Add:  
- unit tests for config loading defaults and required fields  
- HTTP handler tests for /healthz and /readyz using httptest  
```  
  
## What to run  
  
```bash  
make test  
go run ./cmd/openbadger server  
curl http://localhost:8080/healthz  
curl http://localhost:8080/readyz  
```  
  
## Success looks like  
  
- The server can start with environment-based config  
- `/healthz` and `/readyz` return valid responses  
- Logs are structured and readable  
  
---  
  
# STEP 3 — Add PostgreSQL, migrations, and the first schema  
  
## What this means in IT terms  
  
You are adding the database and the first tables.    
This is where the system will remember sites, nodes, jobs, and observations.  
  
## Ask the LLM  
  
```text  
Add PostgreSQL support, migration support, and the first database schema.  
  
Requirements:  
- Use pgx for PostgreSQL connectivity  
- Add a migration system and a migrate mode or command path  
- Add Docker Compose for local PostgreSQL development  
- Create initial SQL migrations for these tables:  
  - sites  
  - nodes  
  - jobs  
  - observations  
- Add a small storage layer or repository layer  
- Keep the schema minimal but aligned with the architecture docs  
- Add a README or comment block showing how to start Postgres and run migrations  
```  
  
## Tests to request  
  
```text  
Add:  
- unit tests for repository helpers where reasonable  
- integration tests for database operations that skip unless TEST_DB_DSN is set  
- tests should create and clean up their own records  
```  
  
## What to run  
  
```bash  
docker compose -f deploy/compose/dev.yml up -d postgres  
go run ./cmd/openbadger migrate  
make test  
```  
  
## Success looks like  
  
- Postgres starts locally  
- Migrations apply cleanly  
- The code can connect to the database  
- Basic CRUD helpers exist for core tables  
  
---  
  
# STEP 4 — Add node enrollment and heartbeat  
  
## What this means in IT terms  
  
This is when collectors and sensors first “check in” with the server.    
Think of it like provisioning a branch appliance so the central controller knows it exists.  
  
## Ask the LLM  
  
```text  
Implement node enrollment and heartbeat.  
  
Requirements:  
- Add POST /api/v1/nodes/enroll  
- Add POST /api/v1/nodes/heartbeat  
- Support both collectors and sensors  
- The server should use a bootstrap enrollment token from config or env  
- On successful enrollment, issue a node token to the enrolling node  
- Store a hashed or otherwise safe representation of node authentication material on the server  
- The collector and sensor should persist their assigned node identity and auth token locally in a state file  
- Heartbeats should update last heartbeat time, version, name, and capabilities  
- Add a small authenticated node client for collector/sensor use  
- Add a dev/debug endpoint to list nodes if that helps manual verification  
```  
  
## Tests to request  
  
```text  
Add:  
- handler tests for enroll and heartbeat endpoints  
- auth tests for node token use  
- collector-side tests for local state persistence  
- integration tests using httptest for enroll -> heartbeat flow  
```  
  
## What to run  
  
```bash  
make test  
go run ./cmd/openbadger server  
go run ./cmd/openbadger collector  
```  
  
## Success looks like  
  
- A collector can enroll  
- The server records the collector  
- Heartbeats update regularly  
- You can see that the collector is “alive”  
  
---  
  
# STEP 5 — Add job leasing and job status updates  
  
## What this means in IT terms  
  
This creates the work-order system.    
The server can now tell a collector: “Go do this task.”  
  
## Ask the LLM  
  
```text  
Implement the first job system.  
  
Requirements:  
- Add job model and repository support for:  
  - queued  
  - running  
  - success  
  - failed  
- Add POST /api/v1/jobs/lease  
- Add POST /api/v1/jobs/{id}/status  
- A collector should poll for eligible jobs based on capability  
- Add lease ownership and lease timeout fields  
- Ensure one job cannot be leased by multiple collectors at the same time  
- Add a simple dev/debug API or helper to create a test job without requiring a UI  
- Update collector mode to:  
  - heartbeat  
  - poll for jobs  
  - accept one leased job  
  - report status changes  
```  
  
## Tests to request  
  
```text  
Add:  
- unit tests for job state transition rules  
- lease-concurrency tests to prove only one node gets a lease  
- handler tests for lease and status endpoints  
```  
  
## What to run  
  
```bash  
make test  
go run ./cmd/openbadger server  
go run ./cmd/openbadger collector  
```  
  
Then create a test job using the dev/debug path the LLM added.  
  
## Success looks like  
  
- The server can create a job  
- The collector can lease it  
- The collector can report completion or failure  
  
---  
  
# STEP 6 — Add observation ingest and a demo runner  
  
## What this means in IT terms  
  
This is the first time the system produces actual evidence records.    
Even if the scan is fake at first, this proves the data pipeline works end to end.  
  
## Ask the LLM  
  
```text  
Implement observation ingest and a small demo job runner.  
  
Requirements:  
- Add observation structs aligned with docs/observation-schema.md  
- Add POST /api/v1/observations/batch  
- Validate required top-level observation fields  
- Store observations in the observations table as JSONB plus important indexed fields  
- Add a collector-side Runner interface if not already present  
- Add one simple dev/demo runner that generates a synthetic observation for a demo job  
- Add a debug endpoint to list recent observations  
- Wire the collector loop so:  
  - it leases a demo job  
  - runs the demo runner  
  - uploads an observation batch  
  - marks the job successful  
```  
  
## Tests to request  
  
```text  
Add:  
- unit tests for observation validation  
- handler tests for batch ingest  
- repository tests for observation insertion  
- collector-side tests for runner execution and upload behavior  
```  
  
## What to run  
  
```bash  
make test  
go run ./cmd/openbadger server  
go run ./cmd/openbadger collector  
```  
  
Then create a demo job and confirm a stored observation exists.  
  
## Success looks like  
  
- A collector can execute a job  
- An observation batch reaches the server  
- Observations are stored in Postgres  
- You now have the backbone of the whole system  
  
---  
  
# STEP 7 — Add target ranges and real ICMP discovery  
  
## What this means in IT terms  
  
Now the collector does a real network task: pinging targets.    
This is the first actual discovery feature.  
  
## Ask the LLM  
  
```text  
Implement target ranges and ICMP discovery.  
  
Requirements:  
- Add target range support:  
  - CIDR ranges  
  - exclusions  
- Add an ICMP runner that emits icmp.alive observations  
- Use a clean abstraction so future scanners fit the same runner model  
- Add a job payload shape for ICMP scan targets  
- Add any required capabilities or privileges documentation  
- Keep the first ICMP implementation small and reliable  
- If raw socket privileges are needed, document that clearly  
```  
  
## Tests to request  
  
```text  
Add:  
- unit tests for target range expansion and exclusions  
- unit tests for ICMP observation normalization  
- optional integration tests that ping a target only if PING_TEST_TARGET is set  
```  
  
## What to run  
  
```bash  
make test  
```  
  
Optional live check:  
  
```bash  
PING_TEST_TARGET=127.0.0.1 go test ./... -run ICMP -v  
```  
  
## Success looks like  
  
- The server can define targets for ICMP work  
- The collector can ping and produce `icmp.alive`  
- This is your first real discovery signal  
  
---  
  
# STEP 8 — Add scan profiles, schedules, and automatic job creation  
  
## What this means in IT terms  
  
You are moving from manual work orders to scheduled operations.    
This is like saying, “Ping this subnet every hour.”  
  
## Ask the LLM  
  
```text  
Implement scan profiles, schedules, and scheduler-driven job creation.  
  
Requirements:  
- Add tables and migrations for:  
  - target_ranges  
  - scan_profiles  
  - schedules  
- Add a scheduler loop in server mode  
- Use cron-like scheduling; robfig/cron is acceptable  
- Scan profiles should capture:  
  - protocol/capability  
  - timeout  
  - retry count  
  - concurrency/rate limit where practical  
  - credential profile reference for future protocols  
- The scheduler should create jobs from active schedules  
- Add simple APIs or debug APIs to create target ranges, scan profiles, and schedules  
```  
  
## Tests to request  
  
```text  
Add:  
- unit tests for schedule parsing  
- tests for next-run calculations  
- integration tests proving a schedule creates jobs  
```  
  
## What to run  
  
```bash  
make test  
go run ./cmd/openbadger server  
```  
  
## Success looks like  
  
- You no longer need to manually create every job  
- The server can generate repeated work automatically  
  
---  
  
# STEP 9 — Add SNMP discovery  
  
## What this means in IT terms  
  
This is when OpenBadger starts learning about network devices, printers, UPSes, and similar equipment.    
SNMP gives you much richer information than ping.  
  
## Ask the LLM  
  
```text  
Implement SNMP scanning for v0.1.  
  
Requirements:  
- Add credential profile support for:  
  - SNMPv2c  
  - SNMPv3  
- Use gosnmp unless there is a strong reason not to  
- Implement these observation types:  
  - snmp.system  
  - snmp.interface  
  - snmp.arp_entry  
  - snmp.fdb_entry  
- Collect, where available:  
  - sysName  
  - sysDescr  
  - sysObjectID  
  - uptime  
  - interfaces  
  - ARP entries  
  - FDB/MAC table entries  
- Normalize output to match docs/observation-schema.md  
- Add a vendor/model mapping helper based on sysObjectID where practical  
- Integrate SNMP jobs into the existing scheduler/job/observation pipeline  
```  
  
## Tests to request  
  
```text  
Add:  
- unit tests for SNMP normalization and parsing helpers  
- tests for credential profile validation  
- optional integration tests controlled by:  
  - SNMP_TEST_TARGET  
  - SNMP_TEST_COMMUNITY  
  - or SNMPv3 env vars  
- if practical, add fixture-based tests or an snmpsim-based integration path  
```  
  
## What to run  
  
```bash  
make test  
```  
  
Optional live check:  
  
```bash  
SNMP_TEST_TARGET=10.0.0.10 SNMP_TEST_COMMUNITY=public go test ./... -run SNMP -v  
```  
  
## Success looks like  
  
- Network devices can produce rich observations  
- You can see useful device identity beyond ping  
  
---  
  
# STEP 10 — Add SSH inventory  
  
## What this means in IT terms  
  
Now OpenBadger can actively inventory Linux and Unix-like hosts.    
This is how it learns OS version, hostname, kernel, and other basic server facts.  
  
## Ask the LLM  
  
```text  
Implement SSH inventory for v0.1.  
  
Requirements:  
- Add credential profiles for:  
  - SSH password auth  
  - SSH key auth  
- Use golang.org/x/crypto/ssh  
- Implement ssh.host observations  
- Collect, where available:  
  - hostname  
  - FQDN  
  - os-release data  
  - kernel version  
  - architecture  
  - SSH host key fingerprint  
  - machine-id where safely available  
- Keep the commands conservative and read-only  
- Normalize to the observation schema  
- Integrate SSH jobs into the existing scheduler and job engine  
```  
  
## Tests to request  
  
```text  
Add:  
- unit tests for parsing os-release or command output  
- tests for SSH credential validation  
- optional integration tests controlled by:  
  - SSH_TEST_HOST  
  - SSH_TEST_USER  
  - SSH_TEST_PASSWORD or SSH_TEST_KEY  
```  
  
## What to run  
  
```bash  
make test  
```  
  
Optional live check:  
  
```bash  
SSH_TEST_HOST=10.0.0.20 SSH_TEST_USER=badger SSH_TEST_PASSWORD=secret go test ./... -run SSH -v  
```  
  
## Success looks like  
  
- Linux hosts can be inventoried  
- The system can produce meaningful host identity data from SSH  
  
---  
  
# STEP 11 — Add WinRM inventory  
  
## What this means in IT terms  
  
This is the Windows inventory path.    
Instead of raw WMI/DCOM complexity, OpenBadger uses WinRM and PowerShell/CIM to collect inventory cleanly from Windows machines.  
  
## Ask the LLM  
  
```text  
Implement WinRM inventory for v0.1.  
  
Requirements:  
- Add WinRM credential profiles  
- Prefer WinRM over HTTPS  
- Allow HTTP only if explicitly enabled in config  
- Use a Go WinRM library and explain the dependency choice  
- Implement winrm.windows_host observations  
- Collect, where available:  
  - hostname  
  - domain or workgroup  
  - OS name  
  - OS version  
  - build number  
  - manufacturer  
  - model  
  - serial number  
  - BIOS/system UUID  
  - network addresses  
- Use PowerShell/CIM queries  
- Normalize to the observation schema  
- Integrate WinRM jobs into the existing scheduler/job pipeline  
```  
  
## Tests to request  
  
```text  
Add:  
- unit tests for Windows inventory normalization  
- credential validation tests  
- optional integration tests controlled by:  
  - WINRM_TEST_HOST  
  - WINRM_TEST_USER  
  - WINRM_TEST_PASSWORD  
  - WINRM_TEST_HTTPS  
```  
  
## What to run  
  
```bash  
make test  
```  
  
Optional live check:  
  
```bash  
WINRM_TEST_HOST=10.0.0.30 WINRM_TEST_USER=Administrator WINRM_TEST_PASSWORD='secret' WINRM_TEST_HTTPS=true go test ./... -run WinRM -v  
```  
  
## Success looks like  
  
- Windows hosts can be inventoried through WinRM  
- OpenBadger now supports the three key active discovery paths:  
  - ICMP  
  - SNMP  
  - SSH  
  - WinRM  
  
---  
  
# STEP 12 — Add assets, sightings, and correlation  
  
## What this means in IT terms  
  
This is where raw scan evidence becomes usable inventory.    
Without this step, you have lots of facts. With this step, you have devices.  
  
## Ask the LLM  
  
```text  
Implement asset correlation v1.  
  
Requirements:  
- Add migrations and storage for:  
  - assets  
  - asset_identifiers  
  - asset_addresses  
  - sightings  
- On observation ingest, run correlation logic or queue it in-process for near-real-time processing  
- Follow the correlation rules from docs/architecture.md and docs/observation-schema.md  
- Prefer strong identifiers:  
  - serial_number  
  - system_uuid  
  - bios_uuid  
  - snmp_engine_id  
  - ssh_host_key_fingerprints  
- Treat IP-only evidence as weak  
- Allow provisional assets from weak evidence  
- Prevent automatic merges when strong identifiers conflict  
- Add read APIs for asset list and asset detail  
- Add CSV export for assets  
```  
  
## Tests to request  
  
```text  
Add:  
- table-driven correlation tests covering:  
  - merge on strong identifier  
  - no merge on conflicting strong identifiers  
  - provisional asset from weak evidence  
  - later merge of provisional asset when stronger evidence appears  
- repository tests for asset persistence  
- tests for CSV export shape  
```  
  
## What to run  
  
```bash  
make test  
```  
  
## Success looks like  
  
- A device discovered by multiple protocols can appear as one asset  
- You now have a real inventory engine, not just a scan log  
  
---  
  
# STEP 13 — Add a basic web UI and local admin login  
  
## What this means in IT terms  
  
Now you can actually use the system as an operator instead of only through tests and debug endpoints.  
  
## Ask the LLM  
  
```text  
Implement a minimal web UI and local admin authentication.  
  
Requirements:  
- Use html/template  
- Do not add a SPA or frontend framework  
- Add a minimal local admin login flow  
- Use secure cookie sessions or an equivalent simple mechanism  
- Add pages for:  
  - login  
  - overview/dashboard  
  - nodes  
  - jobs  
  - schedules  
  - assets  
  - asset detail  
- Reuse existing APIs or handlers where practical  
- Keep the UI simple and functional  
```  
  
## Tests to request  
  
```text  
Add:  
- handler tests for login, page auth redirects, and major pages  
- template rendering smoke tests  
- tests for session middleware if added  
```  
  
## What to run  
  
```bash  
make test  
go run ./cmd/openbadger server  
```  
  
Then browse to the UI.  
  
## Success looks like  
  
- You can log in  
- You can view nodes, jobs, and assets from a browser  
- The product starts to feel real  
  
---  
  
# STEP 14 — Add passive sensor packet metadata capture  
  
## What this means in IT terms  
  
This is the passive discovery path.    
It helps catch devices that do not answer ping, SNMP, SSH, or WinRM but still talk on the network.  
  
## Ask the LLM  
  
```text  
Implement passive packet metadata capture for sensors.  
  
Requirements:  
- Use gopacket unless there is a strong reason not to  
- Sensor mode should support:  
  - live capture from a configured interface  
  - offline parsing from a pcap fixture file for tests  
- Extract only metadata, not payload archives  
- Detect and aggregate:  
  - MAC addresses  
  - ARP  
  - IPv4 / IPv6  
  - VLAN IDs where visible  
  - DHCP hostnames  
  - mDNS names  
  - NBNS names  
- Emit passive.pcap_sighting observations  
- Aggregate locally over short windows instead of one observation per packet  
- Upload batches to the server through the existing observation path  
```  
  
## Tests to request  
  
```text  
Add:  
- fixture-based tests using sample pcap files  
- parser tests for ARP, DHCP, mDNS, NBNS extraction  
- aggregation tests proving multiple packets become one summarized observation  
```  
  
## What to run  
  
```bash  
make test  
```  
  
Optional live check with a test interface if available.  
  
## Success looks like  
  
- Passive discovery works without storing packet payloads  
- A silent-but-chatty device can now be seen by the system  
  
---  
  
# STEP 15 — Add flow-based discovery  
  
## What this means in IT terms  
  
This lets network devices export traffic summaries to OpenBadger.    
It is useful when packet mirroring is unavailable but flow export is easy to enable.  
  
## Ask the LLM  
  
```text  
Implement flow-based discovery for sensors.  
  
Requirements:  
- Add a lightweight UDP flow receiver  
- Support IPFIX and NetFlow v9 for v0.1  
- Keep the design focused on discovery evidence, not deep traffic analytics  
- Aggregate raw flow records into summarized flow.sighting observations  
- Capture, where available:  
  - source/destination activity  
  - byte counts  
  - packet counts  
  - top ports  
  - peer IPs  
  - exporter address  
- If a parsing library is added, isolate it behind an internal adapter interface  
```  
  
## Tests to request  
  
```text  
Add:  
- fixture-based tests using sample flow datagrams  
- aggregation tests  
- optional live UDP receiver test if env vars are set  
```  
  
## What to run  
  
```bash  
make test  
```  
  
## Success looks like  
  
- Devices can be discovered from flow evidence  
- Passive visibility now works even without full packet capture in some environments  
  
---  
  
# STEP 16 — Hardening, retention, and release preparation  
  
## What this means in IT terms  
  
This is the “make it safe and usable” step before you call it a real alpha.  
  
## Ask the LLM  
  
```text  
Implement v0.1 hardening and release-readiness improvements.  
  
Requirements:  
- Encrypt stored credential secrets at rest  
- Redact secrets from logs  
- Add stale-node detection based on missed heartbeats  
- Add observation retention policy support  
- Add basic metrics or operational counters if practical  
- Add installation and first-run documentation  
- Add a v0.1 alpha checklist to the repo  
- Keep all changes aligned with existing architecture and scope docs  
```  
  
## Tests to request  
  
```text  
Add:  
- unit tests for credential encryption/decryption  
- tests for log redaction helpers  
- tests for stale heartbeat evaluation  
- tests for retention cleanup logic  
```  
  
## What to run  
  
```bash  
make test  
```  
  
## Success looks like  
  
- Secrets are handled more safely  
- Old data can be managed  
- The repo is much closer to a usable alpha release  
  
---  
  
# Recommended stop points  
  
If you want natural checkpoints, use these:  
  
## Checkpoint A — Foundation complete  
Stop after Step 6.  
  
At this point you have:  
- server  
- collector  
- enroll  
- heartbeat  
- jobs  
- observation ingest  
  
That is the most important backbone.  
  
## Checkpoint B — Active discovery complete  
Stop after Step 12.  
  
At this point you have:  
- ICMP  
- SNMP  
- SSH  
- WinRM  
- asset correlation  
  
That is already a credible core inventory tool.  
  
## Checkpoint C — v0.1 alpha candidate  
Stop after Step 16.  
  
At this point you have:  
- active discovery  
- passive discovery  
- UI  
- correlation  
- basic hardening  
  
---  
  
# Standard commands to ask the LLM to maintain  
  
As the repo grows, ask the LLM to keep these working:  
  
```bash  
make build  
make test  
make run-server  
make run-collector  
make run-sensor  
go run ./cmd/openbadger migrate  
```  
  
You can also ask for:  
  
```bash  
make test-unit  
make test-integration  
```  
  
if the project gets large enough.  
  
---  
  
# Lab targets you should eventually prepare  
  
These are not required to begin coding, but they are very helpful for v0.1 validation:  
  
- one Linux host with SSH  
- one Windows host or VM with WinRM  
- one SNMP-capable device or SNMP simulator  
- one pcap fixture file  
- one flow-export fixture or exporter  
- local PostgreSQL in Docker  
  
---  
  
# If an LLM tries to do too much  
  
Use this control prompt:  
  
```text  
Please reduce scope. Only implement the requested step. Do not refactor unrelated files. Do not add future features. Keep dependencies minimal. Add tests only for the code touched in this step.  
```  
  
---  
  
# If an LLM gives you code but not tests  
  
Use this control prompt:  
  
```text  
Now add the missing tests for this step. Include unit tests and any integration tests guarded by env vars. Show me exactly how to run them.  
```  
  
---  
  
# If an LLM changes too many files  
  
Use this control prompt:  
  
```text  
Please provide a smaller patch. Limit changes to the packages directly involved in this step. Avoid broad renames, formatting-only edits, and unrelated refactors.  
```  
  
---  
  
# Final advice  
  
The first truly important milestone is **not** SNMP or WinRM.  
  
It is this:  
  
> **A collector enrolls, heartbeats, leases a job, runs it, and uploads observations to the server.**  
  
Once that works, the rest of OpenBadger becomes a sequence of protocol adapters and UI improvements.  
  
That is why the first six steps matter so much.  