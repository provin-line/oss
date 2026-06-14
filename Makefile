# provin OSS — build entry points

DIST := dist

.PHONY: help build test vet lint proto clean

help:
	@echo "Targets:"
	@echo "  make build   — build all binaries into $(DIST)/"
	@echo "  make test    — go test ./..."
	@echo "  make vet     — go vet ./..."
	@echo "  make lint    — vet + hygiene scripts"
	@echo "  make proto   — regenerate gen/ from api/protobuf (requires buf)"
	@echo "  make clean   — remove $(DIST)/"

# Binaries land here as their packages materialize:
#   network/cmd/standalone        → $(DIST)/standalone
#   pipeline/chained/cmd          → $(DIST)/chained
#   pipeline/source/ingest/apipush → $(DIST)/apipush-source
#   pipeline/sink/console         → $(DIST)/console-sink
#   cmd/provin                    → $(DIST)/provin
build:
	@echo "no binaries yet — skeleton phase"

test:
	go test ./...

vet:
	go vet ./...

lint: vet
	cd api/protobuf && buf lint
	@for s in scripts/check-*.sh; do [ -x "$$s" ] && "$$s" || true; done

proto:
	# Generate only dplaax/*; vendored third-party protos (o3co/authz) are
	# compiled for import resolution but not regenerated (their Go comes from the
	# upstream module — regenerating would double-register proto extensions).
	cd api/protobuf && buf generate --path dplaax

clean:
	rm -rf $(DIST)
