# OpenBadger Installation and First Run

## Scope

This guide covers a minimal v0.1 alpha setup for the single OpenBadger binary in these modes:

- `server`
- `collector`
- `sensor`
- `migrate`

It aligns with the modular monolith deployment model described in the existing vision, architecture, and scope documents.

## Prerequisites

- Go 1.25+
- PostgreSQL 15+
- network reachability from collectors and sensors to the central server
- a 32-byte base64-encoded credential encryption key for server-side secret storage

Generate a key with:

```bash
openssl rand -base64 32
```

## Build

From the `openbadger/` directory:

```bash
go build ./cmd/openbadger
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

## First run sequence

### 1. Apply migrations

```bash
./openbadger migrate
```

### 2. Start the server

```bash
./openbadger server
```

The server exposes:

- `http://127.0.0.1:8080/healthz`
- `http://127.0.0.1:8080/readyz`
- `http://127.0.0.1:8080/login`
- `http://127.0.0.1:8080/debug/vars`

### 3. Start a collector

On a host that can reach the site networks:

```bash
export OPENBADGER_COLLECTOR_SERVER_URL='http://127.0.0.1:8080'
export OPENBADGER_COLLECTOR_SITE_ID='site-a'
export OPENBADGER_COLLECTOR_ENROLLMENT_TOKEN='replace-with-bootstrap-token'
./openbadger collector
```

### 4. Start a sensor (optional)

For packet metadata or flow observations:

```bash
export OPENBADGER_SENSOR_SERVER_URL='http://127.0.0.1:8080'
export OPENBADGER_SENSOR_SITE_ID='site-a'
export OPENBADGER_SENSOR_ENROLLMENT_TOKEN='replace-with-bootstrap-token'
export OPENBADGER_SENSOR_INTERFACE='eth0'
./openbadger sensor
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
