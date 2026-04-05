FROM golang:1.25-alpine AS builder

WORKDIR /src

RUN apk add --no-cache ca-certificates tzdata build-base libpcap-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o /out/openbadger ./cmd/openbadger

FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata libpcap && \
    addgroup -S openbadger && \
    adduser -S -G openbadger openbadger && \
    mkdir -p /app /etc/openbadger /var/lib/openbadger && \
    chown -R openbadger:openbadger /app /etc/openbadger /var/lib/openbadger

WORKDIR /app

COPY --from=builder /out/openbadger /usr/local/bin/openbadger

USER openbadger

ENTRYPOINT ["openbadger"]
CMD ["server"]
