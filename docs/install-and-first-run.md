# OpenBadger Installation and First Run

## Scope

This guide covers the v0.1 alpha installation paths that the current scope promises:

- container-based deployment with Docker Compose
- direct single-binary execution for development and manual setups

The product ships as a single `openbadger` binary with these runtime modes:

- `server`
- `collector`
- `sensor`
- `migrate`

The Compose manifests in `openbadger/deploy/compose/` package those same modes into installable services.

## Supported deployment for v0.1

The supported deployment model in scope is Docker Compose with PostgreSQL.

Repository paths:

- server and database Compose files:
  - `openbadger/deploy/compose/postgres-compose.yml`
  - `openbadger/deploy/compose/server-compose.yml`
- site collector Compose file:
  - `openbadger/deploy/compose/site-collector-compose.yml`
- site sensor Compose file:
  - `openbadger/deploy/compose/site-sensor-compose.yml`
- environment templates:
  - `openbadger/deploy/compose/server.env.example`
  - `openbadger/deploy/compose/site-collector.env.example`
  - `openbadger/deploy/compose/site-sensor.env.example`
- container image build:
  - `openbadger/deploy/container/Dockerfile`

## Prerequisites

### For Docker Compose deployment

- Docker Engine with Compose support
- network reachability from collectors and sensors to the central server
- a 32-byte base64-encoded credential encryption key for server-side secret storage

Generate a key with:

```bash
openssl rand -base64 32
```

### For direct binary execution

- Go 1.25+
- PostgreSQL 15+
- `libpcap` runtime and development packages on systems where you build or run the passive sensor mode
- the same network and secret requirements listed above

## Install with Docker Compose

From the `openbadger/` directory:

### 1. Prepare the server environment file

Copy the shipped template and replace the placeholder secrets before first boot:

```bash
cp deploy/compose/server.env.example deploy/compose/server.env
```

Required values to change in `deploy/compose/server.env`:

- `OPENBADGER_SERVER_ENROLLMENT_TOKEN`
- `OPENBADGER_SERVER_ADMIN_PASSWORD`
- `OPENBADGER_SERVER_ADMIN_SESSION_SECRET`
- `OPENBADGER_SERVER_CREDENTIAL_ENCRYPTION_KEY`

### 2. Start PostgreSQL and the server stack

Run:

```bash
docker compose \
  -f deploy/compose/postgres-compose.yml \
  -f deploy/compose/server-compose.yml \
  up -d --build
```

Equivalent Makefile shortcut:

```bash
make docker-up
```

This stack does the following:

1. starts PostgreSQL
2. builds the OpenBadger container image
3. runs `openbadger migrate`
4. starts `openbadger server`

The server exposes:

- `http://127.0.0.1:8080/healthz`
- `http://127.0.0.1:8080/readyz`
- `http://127.0.0.1:8080/login`
- `http://127.0.0.1:8080/debug/vars`

To view logs:

```bash
make docker-logs
```

To stop the server stack:

```bash
make docker-down
```

### 3. Start a collector for a site

Copy the collector template and edit it for the site:

```bash
cp deploy/compose/site-collector.env.example deploy/compose/site-collector.env
```

Review and replace the placeholders in `deploy/compose/site-collector.env`, especially:

- `OPENBADGER_COLLECTOR_SERVER_URL`
- `OPENBADGER_COLLECTOR_SITE_ID`
- `OPENBADGER_COLLECTOR_ENROLLMENT_TOKEN`

Then run:

```bash
docker compose -f deploy/compose/site-collector-compose.yml up -d --build
```

The provided Compose file assumes the collector container should reach the server on the Docker host through:

```text
http://host.docker.internal:8080
```

On Linux, the Compose file includes:

```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

so the collector can resolve the host machine.

### 4. Start a sensor for a site

Copy the sensor template and edit it for the site:

```bash
cp deploy/compose/site-sensor.env.example deploy/compose/site-sensor.env
```

Review and replace the placeholders in `deploy/compose/site-sensor.env`, especially:

- `OPENBADGER_SENSOR_SERVER_URL`
- `OPENBADGER_SENSOR_SITE_ID`
- `OPENBADGER_SENSOR_ENROLLMENT_TOKEN`
- `OPENBADGER_SENSOR_INTERFACE`

Then run:

```bash
docker compose -f deploy/compose/site-sensor-compose.yml up -d --build
```

The sample sensor Compose file uses:

- `network_mode: host`
- `cap_add: [NET_ADMIN, NET_RAW]`

so it can access a real interface for passive capture.

## Direct single-binary build and run

This remains useful for development, testing, or manual installation.

From the `openbadger/` directory, build the binary:

```bash
go build -o ./bin/openbadger ./cmd/openbadger
```

Or install it into your system path with the Makefile:

```bash
make install
```

By default, `make install` writes to `/usr/local/bin/openbadger`. To install somewhere else:

```bash
make install PREFIX=/opt/openbadger
```

## Required server environment

Set these environment variables before first run:

```bash
export OPENBADGER_DATABASE_URL='postgres://openbadger:openbadger@127.0.0.1:5432/openbadger?sslmode=disable'
export OPENBADGER_SERVER_ENROLLMENT_TOKEN='replace-with-bootstrap-token'
export OPENBADGER_SERVER_ADMIN_USERNAME='admin'
export OPENBADGER_SERVER_ADMIN_PASSWORD='replace-with-admin-password'
export OPENBADGER_SERVER_ADMIN_SESSION_SECRET='replace-with-session-secret'
export OPENBADGER_SERVER_CREDENTIAL_ENCRYPTION_KEY='replace-with-base64-32-byte-key'
```

Optional hardening and operations settings:

```bash
export OPENBADGER_SERVER_EXPECTED_HEARTBEAT_INTERVAL='30s'
export OPENBADGER_SERVER_STALE_AFTER_MISSED_HEARTBEATS='3'
export OPENBADGER_SERVER_OBSERVATION_RETENTION='720h'
```

## Direct first-run sequence

### 1. Apply migrations

```bash
./bin/openbadger migrate
```

If you installed the binary into your `PATH`, you can instead run:

```bash
openbadger migrate
```

### 2. Start the server

```bash
./bin/openbadger server
```

If installed globally:

```bash
openbadger server
```

### 3. Start a collector

On a host that can reach the site networks:

```bash
export OPENBADGER_COLLECTOR_SERVER_URL='http://127.0.0.1:8080'
export OPENBADGER_COLLECTOR_SITE_ID='site-a'
export OPENBADGER_COLLECTOR_ENROLLMENT_TOKEN='replace-with-bootstrap-token'
./bin/openbadger collector
```

### 4. Start a sensor (optional)

For packet metadata or flow observations:

```bash
export OPENBADGER_SENSOR_SERVER_URL='http://127.0.0.1:8080'
export OPENBADGER_SENSOR_SITE_ID='site-a'
export OPENBADGER_SENSOR_ENROLLMENT_TOKEN='replace-with-bootstrap-token'
export OPENBADGER_SENSOR_INTERFACE='eth0'
./bin/openbadger sensor
```

## First-run checklist

After the processes are up:

1. sign in to the admin UI
2. verify the collector or sensor shows recent heartbeats on the nodes page
3. create a site-specific credential profile
4. create a target range
5. create a scan profile
6. create a schedule
7. confirm jobs are created and observations arrive
8. confirm assets appear in inventory

## Operational notes

- Credential profile secrets and secret-bearing job payloads are encrypted before storage in PostgreSQL.
- Structured logs redact sensitive values such as passwords, tokens, SNMP communities, passphrases, private keys, and authorization headers.
- Node status becomes `stale` when the last heartbeat exceeds the configured missed-heartbeat threshold.
- Observation retention cleanup runs with the scheduler and deletes raw observations older than the configured retention window.
- `/debug/vars` exposes lightweight operational counters through the Go standard library `expvar` endpoint.
- The container image now pre-creates `/var/lib/openbadger`, so the shipped collector and sensor Compose files can persist state to mounted volumes without requiring extra image customization.