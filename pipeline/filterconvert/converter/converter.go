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

// ValidateSubset checks that doc (a JSON object) contains all top-level fields
// listed in required. Dotted paths are NOT supported; each element of required
// must be a plain top-level key. Returns an error naming the first missing
// field. Returns nil if required is empty or all fields are present.
//
// The check decodes via canon.StrictDecoder so that duplicate keys and
// trailing data in the converter output are caught at the validation boundary,
// consistent with the hard rule: StrictDecoder is the only JSON decode path on
// protocol boundaries (canon/README.md).
func ValidateSubset(doc []byte, required []string) error {
	if len(required) == 0 {
		return nil
	}

	var obj map[string]interface{}
	if err := canon.NewStrictDecoder(doc).Decode(&obj); err != nil {
		return fmt.Errorf("converter: ValidateSubset: invalid JSON: %w", err)
	}

	for _, key := range required {
		if _, ok := obj[key]; !ok {
			return fmt.Errorf("converter: ValidateSubset: missing required field %q", key)
		}
	}

	return nil
}
