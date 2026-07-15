package vcresolver

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/provin-line/oss/vc"
)

// A body may hold several signed forms of one document: re-issuing a proof
// leaves the body — and therefore every successor link — untouched
// (identity.body-address). The old store kept ONE credential per body address
// and let a later write overwrite it, so a valid proof could be evicted by a
// later invalid one, and an invalid proof arriving first could keep the valid
// one out. This file is the layer that ends both: variants are write-once and
// the set is append-only (identity.variant.immutable-set).
//
// WHY A CONCRETE FAÇADE OVER A DUMB BACKEND, and not an interface with a
// conformance suite. A Go interface is a method set, not a capability
// boundary: it can describe "write-once" but cannot enforce it, and a suite
// only constrains the implementations that run it. So the properties that
// matter live HERE, once, in code every backend is behind — id recomputation,
// canonical validation, write-once admission, winner resolution, defensive
// copying. VariantBackend is left with no identity semantics at all: it places
// named bytes and reports whether a name was taken. A hostile or broken
// backend can then withhold data (availability) but cannot forge a variant —
// every byte it returns is validated against the id that was asked for.

// VariantBackend is durable, named byte storage — deliberately ignorant of
// what the names mean. Names are hex payloads (vc.WireVariantHex), so they are
// safe as file names and map keys by construction and a backend never learns
// the id grammar it would otherwise drift from.
//
// Implementations owe exactly three things: PutIfAbsent must be atomic (two
// concurrent calls for one name cannot both create it), reads must return the
// bytes that were written, and listings must be lexicographic, exclusive of
// the cursor, and FULL — a short page means exhausted, so a backend returning
// fewer entries than remain would silently truncate a caller's view of a
// body's evidence. Absence is ErrNotFound; damage is any other error, never
// ErrNotFound (a store that laundered damage into "absent" would let a
// corrupted variant read as one that never existed).
type VariantBackend interface {
	// PutIfAbsent atomically creates the entry (bodyHex, variantHex) with
	// wire, reporting existed=true and leaving the held bytes UNTOUCHED when
	// the name is already taken. The comparison of existing bytes is the
	// façade's job, not the backend's — a backend cannot know what "same
	// document" means.
	PutIfAbsent(bodyHex, variantHex string, wire []byte) (existed bool, err error)
	// ReadVariant returns the bytes held at (bodyHex, variantHex).
	ReadVariant(bodyHex, variantHex string) ([]byte, error)
	// ListVariantHexes pages the variant names held under bodyHex. An unknown
	// body is an empty page, not ErrNotFound: holding no variants is a normal
	// answer, not a claim that none exist.
	ListVariantHexes(bodyHex, fromExclusive string, limit int) ([]string, error)
	// ReadProjection returns the bytes in the body's legacy flat slot.
	ReadProjection(bodyHex string) ([]byte, error)
	// WriteProjection replaces the body's legacy flat slot.
	WriteProjection(bodyHex string, wire []byte) error
	// ListBodyHexes pages every body name held — the UNION of bodies with a
	// projection and bodies with variants. A body known only through one of
	// the two must still be listed: the service's forward index is built from
	// this enumeration, so a body missing here reads as having no successors.
	ListBodyHexes(fromExclusive string, limit int) ([]string, error)
}

// ErrCorrupt is storage holding bytes that are not what their name says they
// are. It is deliberately distinct from ErrNotFound: absent evidence and
// damaged evidence are different facts, and a caller that conflated them
// would report "never seen" for a variant that was tampered with.
var ErrCorrupt = errors.New("vcresolver: corrupt variant")

// VariantStore is the one path to a body's variants. It is concrete on
// purpose: see the file comment.
type VariantStore struct {
	backend VariantBackend
}

// NewVariantStore returns the façade over backend.
func NewVariantStore(backend VariantBackend) *VariantStore {
	return &VariantStore{backend: backend}
}

// PutVariant admits cred into its body's append-only variant set and returns
// the two addresses it was admitted under.
//
// Both addresses are RECOMPUTED from cred: a caller cannot choose where its
// bytes land, so misfiling is not a mistake this API can make. Re-admitting
// the same variant with the same bytes is idempotent; the same variant with
// different bytes is ErrCorrupt (in a healthy store that is unreachable — the
// id is the digest of the bytes — so it fires only for damage or tampering).
//
// A pre-existing body-only entry is materialized into the set FIRST, so the
// bytes that were there before this slice existed become a variant like any
// other rather than being displaced by the new one.
func (s *VariantStore) PutVariant(cred *vc.PipelinePassCredential) (bodyAddress, wireVariantID string, err error) {
	if cred == nil {
		return "", "", fmt.Errorf("%w: nil credential", ErrInvalidArgument)
	}
	// The canonical snapshot is taken once, here, and everything downstream —
	// both ids and the stored bytes — is derived from THAT slice. The caller's
	// credential is never retained, so a caller mutating it afterwards cannot
	// reach into the store.
	wire, err := cred.MarshalJSON()
	if err != nil {
		return "", "", fmt.Errorf("%w: canonicalize credential: %v", ErrInvalidArgument, err)
	}
	bodyAddress, err = cred.Hash()
	if err != nil {
		return "", "", fmt.Errorf("%w: hash credential body: %v", ErrInvalidArgument, err)
	}
	bodyHex, ok := contentAddressHex(bodyAddress)
	if !ok {
		return "", "", fmt.Errorf("%w: credential hashed to %q, not a content address", ErrInvalidArgument, bodyAddress)
	}
	wireVariantID = vc.WireVariantIDOf(wire)
	variantHex, ok := vc.WireVariantHex(wireVariantID)
	if !ok {
		return "", "", fmt.Errorf("%w: derived variant id %q is malformed", ErrInvalidArgument, wireVariantID)
	}

	if err := s.materializeProjection(bodyHex); err != nil {
		return "", "", err
	}
	if err := s.admit(bodyHex, variantHex, wire); err != nil {
		return "", "", err
	}
	// The variant is durable before the projection moves: the projection is a
	// derived pointer, and a crash between the two leaves a stale pointer that
	// the next read heals — while the reverse order could point at evidence
	// that is not there.
	if err := s.refreshProjection(bodyHex); err != nil {
		return "", "", err
	}
	return bodyAddress, wireVariantID, nil
}

// admit is the write-once gate: create, or prove the held bytes are identical.
func (s *VariantStore) admit(bodyHex, variantHex string, wire []byte) error {
	existed, err := s.backend.PutIfAbsent(bodyHex, variantHex, wire)
	if err != nil {
		return fmt.Errorf("vcresolver: admit variant: %w", err)
	}
	if !existed {
		return nil
	}
	held, err := s.backend.ReadVariant(bodyHex, variantHex)
	if err != nil {
		return fmt.Errorf("vcresolver: read back held variant: %w", err)
	}
	if !bytes.Equal(held, wire) {
		return fmt.Errorf("%w: %s holds bytes that are not the document its id names (tampered or misfiled)",
			ErrCorrupt, vc.WireVariantIDFromHex(variantHex))
	}
	return nil
}

// flatSlot is the classified legacy body-only entry. A body's variant set is
// ALWAYS the union of the variant names and this slot: a body written before
// this slice existed, or written by an older binary after a rollback, holds
// bytes only here. Treating the slot as a candidate everywhere is what keeps
// those bytes from reading as absent.
type flatSlot struct {
	present bool
	// hex is the variant this slot's bytes are, or "" when they are not the
	// canonical projection of a credential (damaged).
	hex  string
	wire []byte
}

func (f flatSlot) damaged() bool { return f.present && f.hex == "" }

func (s *VariantStore) readFlat(bodyHex string) (flatSlot, error) {
	wire, err := s.backend.ReadProjection(bodyHex)
	if errors.Is(err, ErrNotFound) {
		return flatSlot{}, nil
	}
	if err != nil {
		return flatSlot{}, fmt.Errorf("vcresolver: read projection: %w", err)
	}
	hex, ok := validatedFlatVariantHexOf(wire, bodyHex)
	if !ok {
		return flatSlot{present: true}, nil
	}
	return flatSlot{present: true, hex: hex, wire: wire}, nil
}

// errOnlyCopyCorrupt is the answer when a body's ONLY copy is damaged.
// Reporting ErrNotFound instead would launder a tampered credential into "this
// node never held it" — a gap in provenance where there is evidence of
// interference.
func errOnlyCopyCorrupt(bodyHex string) error {
	return fmt.Errorf("%w: the legacy entry for body sha256:%s is the only copy and is not the canonical projection of a credential", ErrCorrupt, bodyHex)
}

// materializeProjection copies a body's legacy flat bytes into the variant set
// if they are not already there.
//
// It runs on EVERY put, not only for bodies that have no variants yet: an old
// binary run against this store (a rollback) writes the flat slot without
// knowing about variants, so a body can have both a variant set and a flat
// entry holding something else. Materializing unconditionally is what keeps
// those bytes from being lost when the next put refreshes the projection.
func (s *VariantStore) materializeProjection(bodyHex string) error {
	flat, err := s.readFlat(bodyHex)
	if err != nil {
		return err
	}
	if !flat.present {
		return nil
	}
	// Adopting is the last moment anything can check these bytes: once filed
	// under their own digest, every later fetch serves them as evidence.
	if flat.damaged() {
		return fmt.Errorf("%w: the legacy entry for body sha256:%s is not the canonical projection of a credential, so it cannot be adopted as a variant", ErrCorrupt, bodyHex)
	}
	return s.admit(bodyHex, flat.hex, flat.wire)
}

// refreshProjection points the legacy flat slot at the body's current winner.
//
// The slot exists for readers that do not know about variants — an older
// binary reading this directory after a rollback. New readers never trust it
// (Get recomputes the winner), so a failure to refresh it is not a failure to
// answer correctly; it is only a compatibility artifact going stale.
func (s *VariantStore) refreshProjection(bodyHex string) error {
	winner, wire, err := s.winner(bodyHex)
	if err != nil {
		return err
	}
	if winner == "" {
		return nil
	}
	if held, err := s.backend.ReadProjection(bodyHex); err == nil && bytes.Equal(held, wire) {
		return nil
	}
	if err := s.backend.WriteProjection(bodyHex, wire); err != nil {
		return fmt.Errorf("vcresolver: refresh projection: %w", err)
	}
	return nil
}

// winner returns the body's projected variant (hex) and its bytes, or ("",
// nil, nil) when the body is unknown.
//
// The winner is a pure function of the SET — the lexicographically smallest
// variant id — not of arrival order. Two nodes holding the same variants
// project the same one, and replaying admissions in any order lands on the
// same answer; first-write-wins could not say either. What it is NOT is stable
// over time: a later, smaller variant moves it. That is why the projection is
// provisional and evidence goes through GetVariant
// (identity.resolution.exact-vs-legacy).
func (s *VariantStore) winner(bodyHex string) (variantHex string, wire []byte, err error) {
	page, err := s.backend.ListVariantHexes(bodyHex, "", 1)
	if err != nil {
		return "", nil, fmt.Errorf("vcresolver: list variants: %w", err)
	}
	setMin := ""
	if len(page) > 0 {
		setMin = page[0]
	}

	// The flat slot is always a candidate: this is a read path, so it cannot
	// assume the write path's materialization has run for this body yet.
	flat, err := s.readFlat(bodyHex)
	if err != nil {
		return "", nil, err
	}
	switch {
	case flat.hex != "" && (setMin == "" || flat.hex < setMin):
		return flat.hex, flat.wire, nil
	case flat.damaged() && setMin == "":
		return "", nil, errOnlyCopyCorrupt(bodyHex)
	}
	// A damaged slot does NOT veto a body whose set is intact: the winner
	// below still comes from real evidence.

	if setMin == "" {
		return "", nil, nil
	}
	wire, err = s.readValidated(bodyHex, setMin)
	if err != nil {
		return "", nil, err
	}
	return setMin, wire, nil
}

// validatedFlatVariantHexOf names the variant a legacy flat slot holds — but
// only if those bytes are the canonical projection of a credential AND that
// credential is the body the slot is filed under.
//
// Canonicality is the only witness available for the id: it is derived FROM
// these bytes, so recomputing a digest would compare a value against itself
// and could never fail. Skip the check and re-spelled bytes get filed under
// their own digest, after which every fetch of that id serves bytes no
// signature covers.
//
// The BODY check is the second half, and it is not redundant: canonical bytes
// for a DIFFERENT body are perfectly well-formed, so canonicality alone would
// adopt some other body's credential into this body's variant set. The
// pre-slice store made exactly this check when it read the flat file
// ("tampered or misfiled"); losing it here would be a regression.
func validatedFlatVariantHexOf(wire []byte, bodyHex string) (string, bool) {
	cred, err := validateWire(wire)
	if err != nil {
		return "", false
	}
	got, err := cred.Hash()
	if err != nil || got != "sha256:"+bodyHex {
		return "", false
	}
	return vc.WireVariantHex(vc.WireVariantIDOf(wire))
}

// Get serves the body's legacy projection: the deterministic winner over the
// held variant set, as a decoded credential.
//
// This is NOT evaluation evidence (admission.resolve-vc.legacy-projection).
// It answers "some signed form of this body", which is enough for a chain hole
// and for the content-hash check every verifier runs, and not enough to audit:
// an auditor needs the exact bytes it evaluated, which is GetVariant.
//
// The winner is recomputed from the set on every read rather than read out of
// the flat slot, so a crash between a variant write and a projection refresh
// self-heals here instead of persisting until that body is next written.
func (s *VariantStore) Get(hash string) (*vc.PipelinePassCredential, error) {
	bodyHex, ok := contentAddressHex(hash)
	if !ok {
		return nil, fmt.Errorf("%w: hash %q is not a sha256:<hex> content address", ErrInvalidArgument, hash)
	}
	variantHex, wire, err := s.winner(bodyHex)
	if err != nil {
		return nil, err
	}
	if variantHex == "" {
		return nil, ErrNotFound
	}
	cred, err := validateWire(wire)
	if err != nil {
		return nil, fmt.Errorf("%w: projection of body %s: %v", ErrCorrupt, hash, err)
	}
	if got, err := cred.Hash(); err != nil || got != hash {
		return nil, fmt.Errorf("%w: projection of body %s carries body %s", ErrCorrupt, hash, got)
	}
	s.healProjection(bodyHex, wire)
	return cred, nil
}

// healProjection points the legacy flat slot at wire — the variant this read
// just served — so an older binary reading that file directly sees the same
// document. The answer above does not depend on it, so a read-only or failing
// store still resolves; this is compatibility, not correctness.
//
// It ADOPTS what is there first, and that order is the whole point. The flat
// slot can be the only copy of a variant: after a rollback an older binary
// writes it without knowing variants exist, and nothing has materialized it
// yet. If those bytes lose the tie-break they are not what this read serves —
// so a naive repair would overwrite the sole copy of a held variant, and a
// plain READ would destroy evidence that ListVariantIDs had just reported.
// Nothing is replaced until it is preserved, and if preserving fails, nothing
// is replaced at all.
func (s *VariantStore) healProjection(bodyHex string, wire []byte) {
	flat, err := s.readFlat(bodyHex)
	if err != nil {
		return
	}
	switch {
	case flat.damaged():
		// Not ours to launder. Overwriting bytes this store cannot classify
		// would erase the only trace that something tampered with them; a new
		// reader is unaffected either way, because it serves the set.
		return
	case flat.present && bytes.Equal(flat.wire, wire):
		return // already pointing at what was served
	case flat.present:
		if err := s.admit(bodyHex, flat.hex, flat.wire); err != nil {
			return // could not preserve it, so must not replace it
		}
	}
	_ = s.backend.WriteProjection(bodyHex, wire)
}

// GetVariant returns the exact canonical wire bytes held at (bodyAddress,
// wireVariantID) — the contract evidence needs: byte-for-byte what was
// evaluated, not a re-serialization of an equivalent document
// (admission.resolve-variant.exact).
//
// Three checks stand between storage and the caller, and the first is the one
// that is easy to miss: the bytes must BE the canonical projection, not merely
// canonicalize to it. Re-spelled bytes (extra whitespace, alternate escapes)
// parse to the same document and so recompute to the very id they are filed
// under — a digest-only check waves them through, and the caller receives
// bytes no signature ever covered.
func (s *VariantStore) GetVariant(bodyAddress, wireVariantID string) ([]byte, error) {
	bodyHex, ok := contentAddressHex(bodyAddress)
	if !ok {
		return nil, fmt.Errorf("%w: body %q is not a sha256:<hex> content address", ErrInvalidArgument, bodyAddress)
	}
	variantHex, ok := vc.WireVariantHex(wireVariantID)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a wire variant id", ErrInvalidArgument, wireVariantID)
	}
	wire, err := s.readValidated(bodyHex, variantHex)
	if err != nil {
		return nil, err
	}
	if cred, verr := validateWire(wire); verr == nil {
		if got, herr := cred.Hash(); herr != nil || got != bodyAddress {
			return nil, fmt.Errorf("%w: variant %s under body %s carries body %s (misfiled)",
				ErrCorrupt, wireVariantID, bodyAddress, got)
		}
	}
	return wire, nil
}

// readValidated reads a variant and proves the bytes are the document the id
// names, returning a copy the caller owns.
func (s *VariantStore) readValidated(bodyHex, variantHex string) ([]byte, error) {
	wire, err := s.backend.ReadVariant(bodyHex, variantHex)
	if errors.Is(err, ErrNotFound) {
		return s.readFlatAs(bodyHex, variantHex)
	}
	if err != nil {
		return nil, fmt.Errorf("vcresolver: read variant: %w", err)
	}
	id := vc.WireVariantIDFromHex(variantHex)
	if _, err := validateWire(wire); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrCorrupt, id, err)
	}
	if got := vc.WireVariantIDOf(wire); got != id {
		return nil, fmt.Errorf("%w: %s holds %s (tampered or misfiled)", ErrCorrupt, id, got)
	}
	return append([]byte(nil), wire...), nil
}

// readFlatAs answers an exact fetch from the legacy slot — the union's other
// half. A body written before this slice (or by an older binary after a
// rollback) holds its bytes ONLY there, so a fetch of their id has to find
// them: otherwise migration would present as data loss, and every evidence
// path would read a legacy body as one this node never had.
//
// Damage here is reported rather than answered as absent. A damaged slot's id
// is unknowable, so this store cannot rule out that the bytes asked for are
// the ones that were corrupted, and saying "not held" would turn evidence of
// interference into a clean negative.
func (s *VariantStore) readFlatAs(bodyHex, variantHex string) ([]byte, error) {
	flat, err := s.readFlat(bodyHex)
	if err != nil {
		return nil, err
	}
	switch {
	case flat.hex == variantHex:
		return append([]byte(nil), flat.wire...), nil
	case flat.damaged():
		return nil, fmt.Errorf("%w: body sha256:%s does not hold %s as a variant, and its legacy entry — which could be it — is not the canonical projection of a credential",
			ErrCorrupt, bodyHex, vc.WireVariantIDFromHex(variantHex))
	default:
		return nil, ErrNotFound
	}
}

// validateWire decodes wire under strict rules and proves it IS the canonical
// projection of what it decodes to — the check that separates the document's
// bytes from an equivalent re-spelling of them.
func validateWire(wire []byte) (*vc.PipelinePassCredential, error) {
	var cred vc.PipelinePassCredential
	// Delegates to PipelinePassCredential.UnmarshalJSON, which routes the
	// decode through canon.StrictDecoder (decoder-hygiene-exempt).
	if err := cred.UnmarshalJSON(wire); err != nil {
		return nil, fmt.Errorf("undecodable: %w", err)
	}
	canonical, err := cred.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("uncanonicalizable: %w", err)
	}
	if !bytes.Equal(canonical, wire) {
		return nil, errors.New("bytes are not the canonical projection of the document they decode to")
	}
	return &cred, nil
}

// ListVariantIDs pages a body's variant set in lexicographic order, exclusive
// of fromExclusive. An unknown body yields an empty page — holding no variants
// is a normal answer, not a claim that none exist.
//
// CONSISTENCY IS PER-CALL, not per-iteration: a variant admitted between two
// pages, sorting before the cursor, is not observed by that iteration. Every
// page is exact as of its own call, and the set only grows, so a caller
// needing a complete snapshot either re-lists until nothing new appears or
// works from an evidence view that commits its spine (P0-1 slice B).
func (s *VariantStore) ListVariantIDs(bodyAddress, fromExclusive string, limit int) ([]string, error) {
	bodyHex, ok := contentAddressHex(bodyAddress)
	if !ok {
		return nil, fmt.Errorf("%w: body %q is not a sha256:<hex> content address", ErrInvalidArgument, bodyAddress)
	}
	fromHex := ""
	if fromExclusive != "" {
		fromHex, ok = vc.WireVariantHex(fromExclusive)
		if !ok {
			return nil, fmt.Errorf("%w: cursor %q is not a wire variant id", ErrInvalidArgument, fromExclusive)
		}
	}
	if limit <= 0 {
		return nil, nil
	}
	page, err := s.backend.ListVariantHexes(bodyHex, fromHex, limit)
	if err != nil {
		return nil, fmt.Errorf("vcresolver: list variants: %w", err)
	}
	page, err = s.mergeFlatCandidate(bodyHex, page, fromHex, limit)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(page))
	for _, h := range page {
		out = append(out, vc.WireVariantIDFromHex(h))
	}
	return out, nil
}

// mergeFlatCandidate folds the flat slot's variant into a page of the listing
// when it is not already there — a legacy body, or the rollback case where an
// older binary wrote bytes the set does not contain. Omitting it would hide
// held evidence from every caller that enumerates.
func (s *VariantStore) mergeFlatCandidate(bodyHex string, page []string, fromHex string, limit int) ([]string, error) {
	flat, err := s.readFlat(bodyHex)
	if err != nil {
		return nil, err
	}
	if flat.damaged() {
		// An empty first page plus a damaged slot means every copy this body
		// has is damaged; answering "no variants" would read as a body this
		// node never held. With intact variants in the page, the damaged slot
		// does not veto them — it is reported by the fetch that needs it.
		if len(page) == 0 && fromHex == "" {
			return nil, errOnlyCopyCorrupt(bodyHex)
		}
		return page, nil
	}
	if !flat.present || flat.hex <= fromHex {
		return page, nil
	}
	for _, h := range page {
		if h == flat.hex {
			return page, nil
		}
	}
	// Insert in order, then cut back to the window. The truncation is what
	// keeps the page contract: at most `limit`, and whatever it drops — the
	// candidate itself when it sorts past the window, or the entry it displaced
	// — is still ahead of the cursor, so the next call offers it again.
	//
	// An earlier version short-circuited here when the window was full and the
	// candidate sorted after it. That branch was pure optimization dressed as
	// logic: append-sort-truncate reaches the identical answer, and deleting it
	// changed no test. A branch whose absence is unobservable is a trap for the
	// next reader, not a saving.
	page = append(page, flat.hex)
	sort.Strings(page)
	if len(page) > limit {
		page = page[:limit]
	}
	return page, nil
}

// ListHashes pages the body addresses held, lexicographically and exclusive of
// fromExclusive, returning EXACTLY min(remaining, limit) — the enumeration
// primitive the service's forward index is built from. The full-page rule is
// contract, not convenience: the index infers "store exhausted" from a short
// page, so a truncated page would build a silently incomplete index and answer
// a false "no descendants".
func (s *VariantStore) ListHashes(fromExclusive string, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, nil
	}
	fromHex := ""
	if fromExclusive != "" {
		var ok bool
		if fromHex, ok = contentAddressHex(fromExclusive); !ok {
			// An unparseable cursor is not an error here: the old contract
			// took any string and compared lexicographically, and "" starts
			// at the beginning. A malformed cursor sorts by its own bytes.
			fromHex = strings.TrimPrefix(fromExclusive, "sha256:")
		}
	}
	hexes, err := s.backend.ListBodyHexes(fromHex, limit)
	if err != nil {
		return nil, fmt.Errorf("vcresolver: list bodies: %w", err)
	}
	out := make([]string, 0, len(hexes))
	for _, h := range hexes {
		out = append(out, "sha256:"+h)
	}
	return out, nil
}

// contentAddressHex returns the hex payload of a well-formed content address.
func contentAddressHex(addr string) (string, bool) {
	if !vc.IsContentAddress(addr) {
		return "", false
	}
	return strings.TrimPrefix(addr, "sha256:"), true
}
