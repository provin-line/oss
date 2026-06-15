// Package converter defines the Converter interface and subset output
// validation for the ConvertFlow pipeline step.
//
// A Converter transforms a JSON document into another JSON document.
// Implementations MUST be stateless: the same input always produces the same
// output. A conversion error is a step failure (StatusErrored); a Converter
// never filters (filtering is the responsibility of the filter step).
package converter

import (
	"context"
	"fmt"

	"github.com/provin-line/oss/canon"
)

// Converter transforms a JSON document into another JSON document.
// Implementations MUST be stateless: the same input always produces the same
// output. A conversion error is a step failure (contract.StatusErrored at the
// processor layer); a Converter never filters.
//
// Convert must be safe to call concurrently.
type Converter interface {
	Convert(ctx context.Context, data []byte) ([]byte, error)
}

// RequireFields checks that doc (a JSON object) contains all top-level fields
// listed in fields. Dotted paths are NOT supported; each element of fields
// must be a plain top-level key. Returns an error naming the first missing
// field. Returns nil if fields is empty or all are present.
//
// The check decodes via canon.StrictDecoder so that duplicate keys and
// trailing data in the converter output are caught at the validation boundary,
// consistent with the hard rule: StrictDecoder is the only JSON decode path on
// protocol boundaries (canon/README.md).
func RequireFields(doc []byte, fields []string) error {
	if len(fields) == 0 {
		return nil
	}

	var obj map[string]interface{}
	if err := canon.NewStrictDecoder(doc).Decode(&obj); err != nil {
		return fmt.Errorf("converter: RequireFields: invalid JSON: %w", err)
	}

	for _, key := range fields {
		if _, ok := obj[key]; !ok {
			return fmt.Errorf("converter: RequireFields: missing required field %q", key)
		}
	}

	return nil
}
