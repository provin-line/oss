package urdna2015

import (
	"fmt"

	"github.com/provin-line/oss/internal/excerpt"
)

// panicQuoteLimit bounds the text of a json-gold panic that an error quotes.
const panicQuoteLimit = 128

// fromJSONGold returns what call, a call into json-gold, returns, or an error
// for a panic of it. json-gold asserts the types of values it has not checked,
// and recovers nothing, so a document that fails such an assertion would end
// the goroutine, and the program with it, of a caller canonicalizing what it
// received. Only json-gold's calls run here, with the loader json-gold calls
// back for a context: a panic of the rest of this package's code is not
// caught. Recovering leaves nothing behind: json-gold builds its state
// for each call and keeps none between calls but patterns it only reads, and
// the loader parses a new document for each context it loads.
//
// A call that does not return is a panic whatever recover reports, so a panic
// with a nil value is an error under every GODEBUG setting.
func fromJSONGold(call func() error) (err error) {
	returned := false
	defer func() {
		if returned {
			return
		}
		p := recover()
		err = fmt.Errorf("json-gold panicked: %s", excerpt.Quoted(excerpt.ErrorText(panicValue{p}), panicQuoteLimit))
	}()
	err = call()
	returned = true
	return err
}

// panicValue is the value of a panic as an error, so that excerpt.ErrorText
// takes its text without panicking where its methods do.
type panicValue struct{ value any }

func (p panicValue) Error() string {
	if err, ok := p.value.(error); ok {
		return err.Error()
	}
	return fmt.Sprint(p.value)
}
