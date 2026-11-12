# contentaddress — the content address
> English — 日本語版: [README.ja.md](README.ja.md)

The content address of dPLaaX (the `contentAddress` of its schemas): the
address content is found by, spelled `sha256:` and the 64 lowercase hex digits
of the content's SHA-256.

An `Address` is made only by `Of` (the address of bytes), a `Hasher`'s
`Address` (the same, of bytes written a part at a time) and `Parse` (that one
spelling, and nothing else: no other case, length or surrounding space), so
outside package `unsafe` every `Address` other than the zero one is in its one
spelling and nothing converts to one. Two addresses are equal (`==`) exactly
when their spellings, and so their SHA-256 digests, are equal; an `Address` is
also a map key. The zero `Address` is no address (`IsZero`).

A `Hasher` makes the address of bytes that arrive in parts, such as a stream,
without holding them all: write the parts to it in order (`Write`), then ask
for its `Address`, which is `Of` of those bytes held at once and does not end
it. The zero `Hasher` is ready to use. A `Hasher` is not to be copied
(`go vet` reports a copy), and its methods are not safe for concurrent use.

As JSON text, an `Address` is written and read in its one spelling
(`MarshalText`, `UnmarshalText`). The zero `Address` is not written: a field
that may hold no address is a pointer, nil when there is none, or carries the
`omitzero` option.
