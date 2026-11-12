package payloadresolver

import (
	"github.com/provin-line/oss/contentaddress"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver/wirecontract"
)

// OpRetainPayload points at wirecontract.OpRetainPayload — defined in the
// leaf wirecontract package so a client-only consumer need not
// import this service root; this alias keeps existing call sites
// (payloadresolver.OpRetainPayload, in the storehandler and elsewhere)
// unchanged. See wirecontract.OpRetainPayload for the full doc.
const OpRetainPayload = wirecontract.OpRetainPayload

// RetainPayloadFields returns wirecontract.RetainPayloadFields of its
// arguments — see OpRetainPayload's alias doc. It is a function, not a
// variable, so no importer can change the fields it builds.
func RetainPayloadFields(ownerDID string, declaredSize uint64, contentAddress contentaddress.Address) map[string]any {
	return wirecontract.RetainPayloadFields(ownerDID, declaredSize, contentAddress)
}
