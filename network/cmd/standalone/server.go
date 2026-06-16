package main

import (
	"net/http"
	"path/filepath"

	"connectrpc.com/connect"
	"github.com/o3co/protobuf.interceptors/endpoint"

	"github.com/provin-line/oss/crypto/ed25519"
	didpbconnect "github.com/provin-line/oss/gen/go/dplaax/did/v1/didpbconnect"
	schemapbconnect "github.com/provin-line/oss/gen/go/dplaax/schema/v1/schemapbconnect"
	signerpbconnect "github.com/provin-line/oss/gen/go/dplaax/signer/v1/signerpbconnect"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/auth"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/registry"
	"github.com/provin-line/oss/network/pkg/services/didregistry"
	didhandler "github.com/provin-line/oss/network/pkg/services/didregistry/handler"
	didyaml "github.com/provin-line/oss/network/pkg/services/didregistry/store/yamlstore"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry"
	schemahandler "github.com/provin-line/oss/network/pkg/services/schemaregistry/handler"
	schemayaml "github.com/provin-line/oss/network/pkg/services/schemaregistry/store/yamlstore"
	"github.com/provin-line/oss/network/pkg/services/signer"
	signerhandler "github.com/provin-line/oss/network/pkg/services/signer/handler"
)

// BuildHandler wires the three services into one mux: the Connect RPC services
// sit behind the L1 authorization interceptors (verifier injected — main builds
// it from config, tests inject a static endpoint), while the public W3C DID
// resolution route and /healthz are mounted unauthenticated. Stores root under
// the core data dir in fixed subdirs (dids/, schemas/, keys/) so they never
// cohabit. The registry id and service endpoints come from the registry config.
//
// It is the testable seam: the boot e2e exercises the assembled mux over httptest
// without binding a port; main wraps the returned handler in h2c and serves it.
func BuildHandler(coreCfg *core.CoreConfig, regCfg *registry.RegistryConfig, verifier endpoint.VerifierEndpoint) (http.Handler, error) {
	keyStore := filestore.New(filepath.Join(coreCfg.DataDir, "keys"))
	schemaStore := schemayaml.New(filepath.Join(coreCfg.DataDir, "schemas"))
	didStore := didyaml.New(filepath.Join(coreCfg.DataDir, "dids"))

	schemaSvc := schemaregistry.New(schemaStore)
	signerSvc := signer.New(ed25519.NewSigner(keyStore))
	didSvc := didregistry.New(
		didStore, keyStore, ed25519.Generator{}, ed25519.Verifier{}, regCfg.ID,
		didregistry.WithServiceEndpoints(regCfg.Endpoints),
	)

	authz := connect.WithInterceptors(auth.Interceptors(verifier)...)

	mux := http.NewServeMux()
	for _, p := range []handlerPair{
		newPair(schemapbconnect.NewSchemaServiceHandler(schemahandler.New(schemaSvc), authz)),
		newPair(didpbconnect.NewDIDServiceHandler(didhandler.New(didSvc), authz)),
		newPair(signerpbconnect.NewSignerServiceHandler(signerhandler.New(signerSvc), authz)),
	} {
		mux.Handle(p.path, p.h)
	}

	// Public, unauthenticated routes: W3C DID resolution (open read, slice-4) and
	// liveness. These deliberately carry no authz interceptor.
	mux.Handle("/did/", didhandler.NewResolutionHandler(didSvc, regCfg.ID))
	mux.HandleFunc("/healthz", healthz)

	return mux, nil
}

type handlerPair struct {
	path string
	h    http.Handler
}

// newPair adapts the (path, handler) pair every generated NewXServiceHandler
// returns into a struct for uniform mux registration.
func newPair(path string, h http.Handler) handlerPair {
	return handlerPair{path: path, h: h}
}

func healthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}
