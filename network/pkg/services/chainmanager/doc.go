// Package chainmanager is the cross-pipeline connection control plane: two
// surfaces over one frozen wire (dplaax.chain.v1).
//
// ChainService is the operator-facing L1 surface — JWT-authenticated, every RPC
// carries an o3co.authz.v1.policy option enforced by the network auth
// interceptor. ChainPeerService is the internet-facing L2 surface — it carries
// no L1 policy option; each request instead presents an AuthProof that the
// handler verifies in-band via the wireauth library.
//
// The L1/L2 split is a tested descriptor contract (contract_test.go), asserted
// in both directions: every ChainService RPC carries the policy option, no
// ChainPeerService RPC does, and every ChainPeerService request carries an
// auth_proof field. The subpackages beneath this one supply the data layer the
// services build on: store (subscription + allow-list persistence), allowlist
// (DID-glob trust matching), wireauth (L2 proof signing/verification), evidence
// (durable relationship-evidence log — transfer.relationship.record), and infra
// (transport operators).
package chainmanager
