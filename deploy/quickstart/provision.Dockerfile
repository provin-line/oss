# syntax=docker/dockerfile:1.7
#
# Builds the NATS trust-material provisioner (deploy/quickstart/provision) and
# runs it as a one-shot init container: it writes operator/account seeds, the
# account claims JWT, and nats-server.conf into the shared `provisioned` volume
# before the broker and node start. Build context is the provin.oss module root.

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/provision ./deploy/quickstart/provision

FROM alpine:3.22
COPY --from=build /out/provision /usr/local/bin/provision
# Default writes to /provisioned (the shared volume mount); override with args.
ENTRYPOINT ["provision"]
CMD ["-out", "/provisioned"]
