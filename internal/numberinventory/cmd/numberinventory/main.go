// Command numberinventory scans persisted stores for numbers that the RFC 8785
// canonicalization switch would re-serialize (ForkW-1 §2.2b-1).
//
// Usage:
//
//	go run ./internal/numberinventory/cmd/numberinventory <dir> [<dir>...]
//
// Exit status is 1 when the scan does not clear the switch — either an unsafe
// number was found, or an artifact could not be inspected. Both are blockers:
// an artifact nobody could read is not evidence that it is safe.
package main

import (
	"fmt"
	"os"

	"github.com/provin-line/oss/internal/numberinventory"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: numberinventory <dir> [<dir>...]")
		os.Exit(2)
	}
	roots := os.Args[1:]
	rep, err := numberinventory.Scan(roots...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "numberinventory: %v\n", err)
		os.Exit(2)
	}
	for _, root := range rep.Roots {
		fmt.Printf("root: %s\n", root)
	}
	fmt.Printf("scanned=%d unsafe=%d undecodable=%d\n", rep.Scanned, rep.Unsafe, rep.Undecodable)
	for _, f := range rep.Findings {
		fmt.Printf("  BLOCK %s at %s: %s %s\n", f.File, f.Path, f.Literal, f.Reason)
	}
	if !rep.Safe() {
		fmt.Println("RESULT: BLOCKED — do not switch stored-address canonicalization")
		os.Exit(1)
	}
	fmt.Println("RESULT: CLEAR — no artifact changes bytes under RFC 8785")
}
