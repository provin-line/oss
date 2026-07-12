/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package auth_test

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// httpOnlySurface lists PDP-guarded calls that carry NO proto policy option
// because they are not gRPC methods. Adding an HTTP-only PEP call means
// extending this list, the snapshot, AND the provin.auth scaffold surface in
// the same change.
var httpOnlySurface = []string{
	"ingest:push", // cmd/standalone push.go — the /ingest/<name>/ HTTP push surface
}

var policyOption = regexp.MustCompile(`o3co\.authz\.v1\.policy\)\s*=\s*\{\s*resource:\s*"([^"]+)",\s*action:\s*"([^"]+)"\s*\}`)

// TestPDPSurfaceSnapshot is the drift guard between the network's declared L1
// policy surface and the provin.auth policy-verifier scaffold (pdp-selfhost
// spec B-3, made permanent). The scaffold's DefaultDenyRuleCollector denies
// any (resource, action) not in its `surface` list, so an RPC annotation
// added here without the scaffold change is DEAD ON ARRIVAL in every real
// deployment — and nothing else would catch it until a live token is denied
// (exactly how the tlog:read / ingest:push gap shipped).
//
// The snapshot (testdata/pdp-surface.snapshot) is the lock-step handle: this
// test fails when the protos and the snapshot diverge; the snapshot header
// requires the provin.auth scaffold to be updated in the same change.
func TestPDPSurfaceSnapshot(t *testing.T) {
	got := map[string]bool{}
	for _, p := range httpOnlySurface {
		got[p] = true
	}

	protoRoot := filepath.Join("..", "..", "..", "api", "protobuf", "dplaax")
	var protoFiles int
	err := filepath.Walk(protoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".proto") {
			return nil
		}
		protoFiles++
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range policyOption.FindAllStringSubmatch(string(b), -1) {
			got[m[1]+":"+m[2]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", protoRoot, err)
	}
	if protoFiles == 0 {
		t.Fatalf("no .proto files under %s — the guard is scanning the wrong tree", protoRoot)
	}

	want := map[string]bool{}
	f, err := os.Open(filepath.Join("testdata", "pdp-surface.snapshot"))
	if err != nil {
		t.Fatalf("open snapshot: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		want[line] = true
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read snapshot: %v", err)
	}

	var missing, stale []string
	for pair := range got {
		if !want[pair] {
			missing = append(missing, pair)
		}
	}
	for pair := range want {
		if !got[pair] {
			stale = append(stale, pair)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("policy pairs NOT in the snapshot (new RPC surface?): %v\n"+
			"-> extend the provin.auth policy-verifier scaffold `surface` list in the SAME change, then add the pair(s) to network/pkg/auth/testdata/pdp-surface.snapshot", missing)
	}
	if len(stale) > 0 {
		t.Errorf("snapshot pairs with no proto annotation or httpOnlySurface entry (removed RPC?): %v\n"+
			"-> remove them from the snapshot AND the provin.auth scaffold surface in the same change", stale)
	}
}
