package retention_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/provin-line/oss/contentaddress"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver/internal/retention"
)

// fakeWriter keeps what is written to it, and how it was finalized. Its
// Write fails with writeErr, its Commit with commitErr and its Abort with
// abortErr when they are set.
type fakeWriter struct {
	b                             bytes.Buffer
	writeErr, commitErr, abortErr error
	committed, aborted            int
}

func (w *fakeWriter) Write(p []byte) (int, error) {
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	return w.b.Write(p)
}

func (w *fakeWriter) Commit() (string, error) {
	w.committed++
	if w.commitErr != nil {
		return "", w.commitErr
	}
	return contentaddress.Of(w.b.Bytes()).String(), nil
}

func (w *fakeWriter) Abort() error {
	w.aborted++
	return w.abortErr
}

// declared is the Declaration of a payload of size bytes, within a quota of
// that size.
func declared(t *testing.T, size uint64) retention.Declaration {
	t.Helper()
	d, err := retention.Declare(size, size)
	if err != nil {
		t.Fatalf("Declare(%d, %d): %v", size, size, err)
	}
	return d
}

func TestDeclare(t *testing.T) {
	for _, c := range []struct {
		size, quota uint64
		want        error
	}{
		{0, 10, retention.ErrEmpty},
		{1, 10, nil},
		{10, 10, nil},
		{11, 10, retention.ErrOverQuota},
		{0, 0, retention.ErrEmpty},
		{1, 0, retention.ErrOverQuota},
	} {
		d, err := retention.Declare(c.size, c.quota)
		if !errors.Is(err, c.want) {
			t.Errorf("Declare(%d, %d) = %v, want %v", c.size, c.quota, err, c.want)
		}
		if err != nil && d != (retention.Declaration{}) {
			t.Errorf("Declare(%d, %d) refused, with a Declaration that is not the zero one", c.size, c.quota)
		}
	}
}

// The zero Declaration, the only one made outside Declare, keeps nothing:
// Commit refuses it as ErrEmpty and aborts the writer.
func TestRetention_TheZeroDeclarationKeepsNothing(t *testing.T) {
	w := &fakeWriter{}
	r := retention.New(w, retention.Declaration{}, contentaddress.Of(nil))
	if _, err := r.Commit(); !errors.Is(err, retention.ErrEmpty) {
		t.Errorf("Commit: %v, want ErrEmpty", err)
	}
	if w.aborted != 1 || w.committed != 0 {
		t.Errorf("aborted %d, committed %d; want aborted once, not committed", w.aborted, w.committed)
	}
}

// A Declaration Declare refused keeps nothing either.
func TestRetention_ARefusedDeclarationKeepsNothing(t *testing.T) {
	for _, c := range []struct{ size, quota uint64 }{{0, 10}, {11, 10}} {
		d, _ := retention.Declare(c.size, c.quota)
		w := &fakeWriter{}
		r := retention.New(w, d, contentaddress.Of(nil))
		if _, err := r.Commit(); err == nil || w.committed != 0 {
			t.Errorf("Declare(%d, %d) refused, then Commit: %v, committed %d; want an error and nothing committed", c.size, c.quota, err, w.committed)
		}
	}
}

// Bytes that meet the declared size and address are committed, in parts,
// and Commit gives the writer's address.
func TestRetention_CommitsTheBytesTheDeclarationNames(t *testing.T) {
	payload := []byte("hello, payload")
	w := &fakeWriter{}
	r := retention.New(w, declared(t, uint64(len(payload))), contentaddress.Of(payload))
	for _, part := range [][]byte{payload[:5], payload[5:]} {
		if err := r.Write(part); err != nil {
			t.Fatalf("Write(%q): %v", part, err)
		}
	}
	addr, err := r.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if addr != contentaddress.Of(payload).String() || w.committed != 1 || w.aborted != 0 || !bytes.Equal(w.b.Bytes(), payload) {
		t.Errorf("Commit = %q; writer has %q, committed %d, aborted %d; want the payload committed once under its address", addr, w.b.Bytes(), w.committed, w.aborted)
	}
}

// Bytes beyond the declared size are refused before they reach the writer,
// and the writer is aborted.
func TestRetention_RefusesBytesBeyondTheDeclaredSize(t *testing.T) {
	w := &fakeWriter{}
	r := retention.New(w, declared(t, 3), contentaddress.Of([]byte("abc")))
	if err := r.Write([]byte("ab")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := r.Write([]byte("cd")); !errors.Is(err, retention.ErrOverrun) {
		t.Errorf("Write past the declared size: %v, want ErrOverrun", err)
	}
	if w.b.String() != "ab" || w.aborted != 1 || w.committed != 0 {
		t.Errorf("writer has %q, aborted %d, committed %d; want ab, aborted once", w.b.String(), w.aborted, w.committed)
	}
}

// The writer's own error from Write is returned as it is, and the writer is
// aborted.
func TestRetention_AWritersErrorAbortsIt(t *testing.T) {
	down := errors.New("disk gone")
	w := &fakeWriter{writeErr: down}
	r := retention.New(w, declared(t, 3), contentaddress.Of([]byte("abc")))
	if err := r.Write([]byte("abc")); !errors.Is(err, down) {
		t.Errorf("Write: %v, want the writer's error", err)
	}
	if w.aborted != 1 || w.committed != 0 {
		t.Errorf("aborted %d, committed %d; want aborted once", w.aborted, w.committed)
	}
}

// Bytes short of the declared size are not committed: the writer is aborted.
func TestRetention_RefusesBytesShortOfTheDeclaredSize(t *testing.T) {
	w := &fakeWriter{}
	r := retention.New(w, declared(t, 4), contentaddress.Of([]byte("abcd")))
	if err := r.Write([]byte("abc")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := r.Commit(); !errors.Is(err, retention.ErrShort) {
		t.Errorf("Commit: %v, want ErrShort", err)
	}
	if w.aborted != 1 || w.committed != 0 {
		t.Errorf("aborted %d, committed %d; want aborted once, not committed", w.aborted, w.committed)
	}
}

// Bytes of the declared size that are not the ones the declared address
// names are not committed: the writer is aborted.
func TestRetention_RefusesBytesThatAreNotTheDeclaredAddress(t *testing.T) {
	w := &fakeWriter{}
	r := retention.New(w, declared(t, 3), contentaddress.Of([]byte("abc")))
	if err := r.Write([]byte("abd")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := r.Commit(); !errors.Is(err, retention.ErrAddressMismatch) {
		t.Errorf("Commit: %v, want ErrAddressMismatch", err)
	}
	if w.aborted != 1 || w.committed != 0 {
		t.Errorf("aborted %d, committed %d; want aborted once, not committed", w.aborted, w.committed)
	}
}

// Bytes both short of the declared size and not the declared address's are
// refused as short.
func TestRetention_ShortIsCheckedBeforeTheAddress(t *testing.T) {
	w := &fakeWriter{}
	r := retention.New(w, declared(t, 4), contentaddress.Of([]byte("abcd")))
	if err := r.Write([]byte("abd")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := r.Commit(); !errors.Is(err, retention.ErrShort) {
		t.Errorf("Commit: %v, want ErrShort", err)
	}
}

// The writer's own error from Commit is returned as it is; the writer,
// which has finalized, is not aborted.
func TestRetention_AWritersCommitErrorIsReturned(t *testing.T) {
	down := errors.New("disk gone")
	w := &fakeWriter{commitErr: down}
	r := retention.New(w, declared(t, 3), contentaddress.Of([]byte("abc")))
	if err := r.Write([]byte("abc")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := r.Commit(); !errors.Is(err, down) {
		t.Errorf("Commit: %v, want the writer's error", err)
	}
	if w.committed != 1 || w.aborted != 0 {
		t.Errorf("committed %d, aborted %d; want committed once, not aborted", w.committed, w.aborted)
	}
}

// Abort aborts the writer, for a stream that fails outside the bytes, and
// returns the writer's error.
func TestRetention_AbortAbortsTheWriter(t *testing.T) {
	gone := errors.New("already finalized")
	w := &fakeWriter{abortErr: gone}
	r := retention.New(w, declared(t, 3), contentaddress.Of([]byte("abc")))
	if err := r.Abort(); !errors.Is(err, gone) {
		t.Errorf("Abort: %v, want the writer's error", err)
	}
	if w.aborted != 1 || w.committed != 0 {
		t.Errorf("aborted %d, committed %d; want aborted once", w.aborted, w.committed)
	}
}
