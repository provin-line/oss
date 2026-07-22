# provin OSS — build entry points

DIST := dist

.PHONY: help build test vet lint proto conformance clean

help:
	@echo "Targets:"
	@echo "  make build        — build all binaries into $(DIST)/"
	@echo "  make test         — go test ./..."
	@echo "  make vet          — go vet ./..."
	@echo "  make lint         — vet + hygiene scripts"
	@echo "  make proto        — regenerate gen/ from api/protobuf (requires buf)"
	@echo "  make conformance  — run the dplaax conformance harness (every vector runs or is ledgered)"
	@echo "  make clean        — remove $(DIST)/"

# Binaries land here as their packages materialize:
#   cmd/standalone                → $(DIST)/standalone   [built]
#   cmd/network                   → $(DIST)/network      [built]
#   cmd/pipeline                  → $(DIST)/pipeline     [built]
#   cmd/provin                    → $(DIST)/provin       [built]
#   pipeline/sink/console         → $(DIST)/console-sink
build:
	mkdir -p $(DIST)
	go build -o $(DIST)/standalone ./cmd/standalone
	go build -o $(DIST)/network ./cmd/network
	go build -o $(DIST)/pipeline ./cmd/pipeline
	go build -o $(DIST)/provin ./cmd/provin

test:
	go test ./...

vet:
	go vet ./...

lint: vet
	cd api/protobuf && buf lint
	@for s in scripts/check-*.sh; do [ -e "$$s" ] || continue; "$$s" || exit 1; done

proto:
	# Generate only dplaax/*; vendored third-party protos (o3co/authz) are
	# compiled for import resolution but not regenerated (their Go comes from the
	# upstream module — regenerating would double-register proto extensions).
	cd api/protobuf && buf generate --path dplaax

# The dplaax conformance harness: TestDplaaxAllVectors proves every vector in
# MANIFEST.sha256 runs or is ledgered as a reasoned skip, then executes them.
# TestCheckCoverage pins the completeness guard; TestDplaaxVendoredManifest pins
# the vendored copies byte-exact. Run standalone so a red here is unambiguous.
conformance:
	go test ./conformance/ -v

clean:
	rm -rf $(DIST)
