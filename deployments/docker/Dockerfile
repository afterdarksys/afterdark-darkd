# Build stage
FROM golang:1.25.7-alpine AS builder

RUN apk add --no-cache git make

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 make build

# Runtime stage
FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata

RUN addgroup -S -g 101 afterdark && adduser -S -u 100 afterdark -G afterdark

COPY --from=builder /src/dist/afterdark-darkd /usr/local/bin/
COPY --from=builder /src/dist/afterdark-darkdadm /usr/local/bin/
COPY --from=builder /src/dist/darkapi /usr/local/bin/

RUN mkdir -p /etc/afterdark /var/lib/afterdark /var/log/afterdark /var/run/afterdark && \
    chown -R afterdark:afterdark /var/lib/afterdark /var/log/afterdark /var/run/afterdark

COPY deployments/docker/darkd.yaml /etc/afterdark/darkd.yaml

USER afterdark

VOLUME ["/var/lib/afterdark", "/var/log/afterdark"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s CMD ["/usr/local/bin/afterdark-darkdadm", "status", "--token-file", "/var/lib/afterdark/.auth_token", "--socket", "/var/run/afterdark/darkd.sock", "--json"]

ENTRYPOINT ["/usr/local/bin/afterdark-darkd"]
CMD ["run", "--config", "/etc/afterdark/darkd.yaml"]
