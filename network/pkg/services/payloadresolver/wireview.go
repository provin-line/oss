package payloadresolver

import "github.com/provin-line/oss/network/pkg/services/payloadresolver/wirecontract"

// OpRetainPayload points at wirecontract.OpRetainPayload — moved into the
// leaf wirecontract package (PR3b Task 2) so a client-only consumer need not
// import this service root; this alias keeps existing call sites
// (payloadresolver.OpRetainPayload, in the storehandler and elsewhere)
// unchanged. See wirecontract.OpRetainPayload for the full doc.
const OpRetainPayload = wirecontract.OpRetainPayload

// RetainPayloadFields points at wirecontract.RetainPayloadFields — see
// OpRetainPayload's alias doc.
var RetainPayloadFields = wirecontract.RetainPayloadFields
