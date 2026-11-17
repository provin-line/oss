// Package vectors checks provin OSS against third-party standard test
// vectors: Wycheproof, RFC 8785 and the JSON-Schema-Test-Suite. It has no
// production code. The vectors are under testdata/, pinned by SHA-256 in
// testdata/SOURCES.tsv; tests read them and never run anything from them.
// The results that differ from a vector's own expectation are listed, with
// their reasons, in <suite>.expected.tsv (see ../README.md).
package vectors
