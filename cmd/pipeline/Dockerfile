# provin pipeline node image — the data-plane deployment root: STL
# (short-lived, per-execution), wire-composed against a cmd/network registry;
# carries no in-process registry of its own.
#
# Build from the repository root (the Go module root is the build context):
#
#   docker build -t provin-line/pipeline:local -f cmd/pipeline/Dockerfile .
#
# Configuration is HOCON, read from the file named by the REQUIRED CONFIG_FILE
# environment variable (the CONFIG_FILE convention — unlike cmd/network's
# ./config/application.conf + CONFIG_OVERLAY layering, this short-lived,
# per-execution binary has no default location to fall back to; relative
# `include` directives inside that file resolve against the file's own
# directory, not the working directory) — mount the config directory and
# point CONFIG_FILE at the file within it:
#
#   docker run -v ./config:/app/config -e CONFIG_FILE=/app/config/application.conf \
#     -p 8443:8443 provin-line/pipeline:local

FROM golang:1.25.5-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/pipeline ./cmd/pipeline

FROM alpine:3.22
RUN adduser -D -u 10001 provin
WORKDIR /app
COPY --from=build /out/pipeline /usr/local/bin/pipeline
# Default data dir (provin.network.core.data-dir); override via config.
RUN mkdir -p /app/data && chown -R provin /app
USER provin
EXPOSE 8443
ENTRYPOINT ["pipeline"]
