.PHONY: build test lint migrate run-server run-collector run-sensor install docker-build docker-up docker-down docker-logs

BINARY := bin/openbadger
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DOCKER_COMPOSE ?= docker compose
SERVER_COMPOSE_FILES := -f deploy/compose/postgres-compose.yml -f deploy/compose/server-compose.yml

build:
	mkdir -p $(dir $(BINARY))
	go build -o $(BINARY) ./cmd/openbadger

test:
	go test ./...

lint:
	golangci-lint run

migrate: build
	@if [ -z "$$OPENBADGER_DATABASE_URL" ]; then echo "OPENBADGER_DATABASE_URL is required" >&2; exit 1; fi
	./$(BINARY) migrate

run-server: build
	./$(BINARY) server

run-collector: build
	./$(BINARY) collector

run-sensor: build
	./$(BINARY) sensor

install: build
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 0755 "$(BINARY)" "$(DESTDIR)$(BINDIR)/openbadger"

docker-build:
	$(DOCKER_COMPOSE) $(SERVER_COMPOSE_FILES) build

docker-up:
	$(DOCKER_COMPOSE) $(SERVER_COMPOSE_FILES) up -d --build

docker-down:
	$(DOCKER_COMPOSE) $(SERVER_COMPOSE_FILES) down

docker-logs:
	$(DOCKER_COMPOSE) $(SERVER_COMPOSE_FILES) logs -f server
