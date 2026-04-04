#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${OPENBADGER_DATABASE_URL:-}" ]]; then
	echo "OPENBADGER_DATABASE_URL is required" >&2
	exit 1
fi

go run ./cmd/openbadger migrate
