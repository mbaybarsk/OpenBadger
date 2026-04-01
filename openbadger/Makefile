.PHONY: build test lint migrate run-server run-collector run-sensor

build:
	go build -o bin/openbadger ./cmd/openbadger

test:
	go test ./...

lint:
	golangci-lint run

run-server: build
	./bin/openbadger server

run-collector: build
	./bin/openbadger collector

run-sensor: build
	./bin/openbadger sensor
