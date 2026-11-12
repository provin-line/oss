package yamlstore_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/network/pkg/services/didregistry/store/yamlstore"
)

// contractStore is a store holding an owner, a pipeline and a process under
// root, and a second process whose document and delegation do not decode.
func contractStore(t *testing.T) (*yamlstore.Store, string) {
	t.Helper()
	root := t.TempDir()
	s := yamlstore.New(root)
	const corrupt = pipelineDID + ":process:corrupt"
	if err := s.SaveOwner(mustParse(t, ownerDID), doc(ownerDID, ownerDID)); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePipeline(mustParse(t, pipelineDID), doc(pipelineDID, ownerDID), sampleDelegation(pipelineDID)); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{processDID, corrupt} {
		if err := s.SaveProcess(mustParse(t, p), doc(p, pipelineDID), sampleDelegation(p)); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(root, "org", "acme", "pipelines", "p1", "processes", "corrupt")
	for _, f := range []string{"document.json", "delegation.json"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return s, corrupt
}

// Resolve and ResolveDelegation answer with a value or an error, never with
// neither (store.DIDStore): for what the store holds, what it does not, what
// it holds but cannot decode, and a DID it refuses to place.
func TestResolveAndResolveDelegation_ReturnAValueOrAnError(t *testing.T) {
	s, corrupt := contractStore(t)
	dids := []*dplaax.DID{
		mustParse(t, ownerDID),
		mustParse(t, pipelineDID),
		mustParse(t, processDID),
		mustParse(t, corrupt),
		mustParse(t, ownerDID+"x"),
		mustParse(t, pipelineDID+":process:absent"),
		{Method: "dplaax", Registry: "poc.dplaax.dev", AccountType: "org", AccountID: ".."},
		nil,
	}
	for _, d := range dids {
		if got, err := s.Resolve(d); got == nil && err == nil {
			t.Errorf("Resolve(%v): neither a document nor an error", d)
		}
		if got, err := s.ResolveDelegation(d); got == nil && err == nil {
			t.Errorf("ResolveDelegation(%v): neither a delegation nor an error", d)
		}
	}
	// What the store holds answers with a value: every document, and the
	// delegation of the pipeline and of the process (an owner has none).
	for _, d := range []string{ownerDID, pipelineDID, processDID} {
		if got, err := s.Resolve(mustParse(t, d)); got == nil || err != nil {
			t.Errorf("Resolve(%s): %v, %v, want its document", d, got, err)
		}
	}
	for _, d := range []string{pipelineDID, processDID} {
		if got, err := s.ResolveDelegation(mustParse(t, d)); got == nil || err != nil {
			t.Errorf("ResolveDelegation(%s): %v, %v, want its delegation", d, got, err)
		}
	}
}
