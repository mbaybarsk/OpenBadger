.PHONY: build test lint migrate run-server run-collector run-sensor

BINARY := bin/openbadger

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
