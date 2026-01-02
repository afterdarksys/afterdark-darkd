# Build stage
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git make

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN make build

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

RUN addgroup -S afterdark && adduser -S afterdark -G afterdark

COPY --from=builder /src/afterdark-darkd /usr/local/bin/
COPY --from=builder /src/afterdark-darkdadm /usr/local/bin/
COPY --from=builder /src/darkapi /usr/local/bin/

RUN mkdir -p /etc/afterdark /var/lib/afterdark /var/log/afterdark /var/run/afterdark && \
    chown -R afterdark:afterdark /var/lib/afterdark /var/log/afterdark /var/run/afterdark

COPY configs/darkd.yaml.example /etc/afterdark/darkd.yaml

USER afterdark

VOLUME ["/var/lib/afterdark", "/var/log/afterdark"]

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/afterdark-darkd"]
CMD ["--config", "/etc/afterdark/darkd.yaml"]
