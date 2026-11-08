package vc

// The tests of package vc (and of vc_test, built into the same binary) issue
// and verify eddsa-rdfc-2022 proofs, so they register the suite as a process
// that uses it does. vc/internal/rdfcclosed tests a process that does not.
func init() { RegisterEdDSARDFC2022() }
