package chainmanager

import "github.com/provin-line/oss/network/pkg/services/chainmanager/wirecontract"

// OpReportEmitHealth points at wirecontract.OpReportEmitHealth — moved into
// the leaf wirecontract package (PR3b Task 8, applying the T2 split
// auditor/payloadresolver/tlogservice already had) so a client-only consumer
// (reportclient, and transitively cmd/pipeline) need not import this service
// root; this alias keeps existing call sites (chainmanager.OpReportEmitHealth,
// in the handler and its tests) unchanged. See wirecontract.OpReportEmitHealth
// for the full doc.
const OpReportEmitHealth = wirecontract.OpReportEmitHealth

// ReportEmitHealthFields points at wirecontract.ReportEmitHealthFields — see
// OpReportEmitHealth's alias doc.
var ReportEmitHealthFields = wirecontract.ReportEmitHealthFields
