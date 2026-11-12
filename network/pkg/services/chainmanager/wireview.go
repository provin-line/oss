package chainmanager

import "github.com/provin-line/oss/network/pkg/services/chainmanager/wirecontract"

// OpReportEmitHealth points at wirecontract.OpReportEmitHealth, which lives in
// the leaf wirecontract package (the same split auditor/payloadresolver/tlogservice
// use) so a client-only consumer (reportclient, and transitively cmd/pipeline)
// need not import this service root; this alias keeps the call sites that name
// chainmanager.OpReportEmitHealth (the handler and its tests) working. See
// wirecontract.OpReportEmitHealth for the full doc.
const OpReportEmitHealth = wirecontract.OpReportEmitHealth

// ReportEmitHealthFields points at wirecontract.ReportEmitHealthFields — see
// OpReportEmitHealth's alias doc.
var ReportEmitHealthFields = wirecontract.ReportEmitHealthFields
