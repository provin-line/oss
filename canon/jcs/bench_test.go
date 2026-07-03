package jcs

import (
	"fmt"
	"testing"
)

// Paper 04 §6.2 Table 4 (BENCH-RETAKE on provin): JCS canonicalization latency vs field count.
// The document mixes strings, numbers, and a nested object so the canonical sort/encode work is
// representative of a credential body rather than a flat string map.

func benchDoc(fields int) map[string]any {
	m := make(map[string]any, fields)
	for i := 0; i < fields; i++ {
		switch i % 4 {
		case 0:
			m[fmt.Sprintf("f%02d_str", i)] = fmt.Sprintf("value-%d-abcdefghijklmnop", i)
		case 1:
			m[fmt.Sprintf("f%02d_num", i)] = float64(i)*3.14159 + 1
		case 2:
			m[fmt.Sprintf("f%02d_bool", i)] = i%2 == 0
		default:
			m[fmt.Sprintf("f%02d_obj", i)] = map[string]any{"k": i, "s": "nested"}
		}
	}
	return m
}

var sinkBytes []byte

func BenchmarkCanonicalize(b *testing.B) {
	for _, n := range []int{5, 20, 50} {
		doc := benchDoc(n)
		b.Run(fmt.Sprintf("%dfields", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				out, err := Canonicalize(doc)
				if err != nil {
					b.Fatalf("canonicalize: %v", err)
				}
				sinkBytes = out
			}
		})
	}
}
