# provin network node image — registry control plane only; pipeline loops
# run in the pipeline runtime.
#
# Build from the repository root (the Go module root is the build context):
#
#   docker build -t provin-line/network:local -f cmd/network/Dockerfile .
#
# Configuration is HOCON, read from ./config/application.conf relative to the
# working directory (/app), with an optional overlay file named by the
# CONFIG_OVERLAY environment variable — mount the config directory (and any
# overlay) at runtime:
#
#   docker run -v ./config:/app/config -p 8443:8443 provin-line/network:local

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/network ./cmd/network

FROM alpine:3.22
RUN adduser -D -u 10001 provin
WORKDIR /app
COPY --from=build /out/network /usr/local/bin/network
# Default data dir (provin.network.core.data-dir); override via config.
RUN mkdir -p /app/data && chown -R provin /app
USER provin
EXPOSE 8443
ENTRYPOINT ["network"]
