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
#   pipeline/filterconvert/cmd    → $(DIST)/filterconvert
#   pipeline/originsource/externalsource/apipush → $(DIST)/apipush-source
#   pipeline/externalsink/console → $(DIST)/console-sink
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
	cd api/protobuf && buf generate

clean:
	rm -rf $(DIST)
