// Added by 1o1 Co. Ltd. for github.com/provin-line/oss; not upstream code.
// See README.md in this directory.

package jsonschema

// Work budget: tests of the local patch to v6.0.3 (see budget.go).

import (
	"math"
	"testing"
)

// The steps a charge multiplies are counted in int64, as the budget is, and
// saturate instead of overflowing: a product past the largest int64 is the
// largest int64, so it exceeds any budget. A product past the largest 32-bit
// int is counted whole, so a 32-bit build charges what a 64-bit one does.
func TestProduct_Saturates(t *testing.T) {
	for _, c := range []struct{ a, b, want int64 }{
		{0, math.MaxInt64, 0}, {3, 4, 12}, {1 << 31, 1 << 10, 1 << 41},
		{math.MaxInt64, 2, math.MaxInt64}, {math.MaxInt64 / 2, 3, math.MaxInt64},
	} {
		if got := product(c.a, c.b); got != c.want {
			t.Errorf("product(%d, %d) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// A charge of more steps than a 32-bit int holds takes them all from the
// budget: one past what is left exceeds it, and one within leaves the rest.
func TestSpendSteps_ChargesPastTheLargest32BitInt(t *testing.T) {
	b := &workBudget{left: 3 << 31}
	if !b.spendSteps(product(1<<31, 2)) || b.left != 1<<31 {
		t.Errorf("spendSteps(2^32) from 3·2^31: left %d, exceeded %v", b.left, b.exceeded)
	}
	if b.spendSteps(product(1<<31, 1)+1) || !b.exceeded {
		t.Errorf("spendSteps(2^31+1) from 2^31: left %d, exceeded %v", b.left, b.exceeded)
	}
}

// A negative charge exceeds the budget rather than adding to it.
func TestSpend_RefusesANegativeCharge(t *testing.T) {
	b := &workBudget{left: 10}
	if b.spend(-5) || !b.exceeded || b.left != 0 {
		t.Errorf("spend(-5): left %d, exceeded %v", b.left, b.exceeded)
	}
}

// A size a RegexpEngine's Regexp gives below zero counts as none.
func TestPatternSize_IgnoresANegativeSize(t *testing.T) {
	if got := patternSize(negativeSize{}); got != 0 {
		t.Errorf("patternSize = %d, want 0", got)
	}
}

type negativeSize struct{ Regexp }

func (negativeSize) Size() int { return -1 << 20 }

// Reading a number costs one step per byte of its text and one per unit of
// its exponent; an exponent too long to read costs more than any budget.
func TestNumberSteps_CountsTheTextAndTheExponent(t *testing.T) {
	for _, c := range []struct {
		text string
		want int64
	}{
		{"12.5", 4}, {"1e40", 4 + 40}, {"1E-40", 5 + 40}, {"-2.5e+3", 7 + 3},
		{"1e99999999999999999999", math.MaxInt64},
	} {
		if got := numberSteps(c.text); got != c.want {
			t.Errorf("numberSteps(%q) = %d, want %d", c.text, got, c.want)
		}
	}
}

// A sum of steps saturates as a product does.
func TestSumSteps_Saturates(t *testing.T) {
	if got := sumSteps(math.MaxInt64-1, 2); got != math.MaxInt64 {
		t.Errorf("sumSteps(MaxInt64-1, 2) = %d", got)
	}
	if got := sumSteps(3, 4); got != 7 {
		t.Errorf("sumSteps(3, 4) = %d", got)
	}
}
