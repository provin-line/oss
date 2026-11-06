# keybinding — key bindings and revocation lists

A **key binding** is a credential in which an issuer states that a key belongs
to a subject — of a kind, with roles, of a key class — for one relying party,
for a period, with an entry in the issuer's revocation list. A relying party
verifies it against its trust anchor for the issuer and the issuer's
revocation list it already holds; it does not ask the issuer at decision time.

- `Issue` signs a `Binding` as a `KeyBindingCredential` (W3C VC Data Model 2.0,
  eddsa-jcs-2022). `IssueStatusList` signs the issuer's revocation list as a W3C
  `BitstringStatusListCredential`. An index marked stays marked in every later
  list of that id, and is not given to another binding.
- `Verifier.VerifyStatusList` checks a list and returns it, current at the
  given time; a list never moves back (an older `validFrom`, or the same one
  with another body, is refused), a later list never clears a mark of the
  held one (a revocation is not reversible; a mark past the end of a shorter
  list counts as cleared), a list dated in the future is not taken, and a
  list's id is a DID URL of its issuer. A `StatusList` cannot be changed once
  verified, and it counts — to decide, and as the held list — only while its
  signing key is among the anchor's issuance keys. With no held list, any
  current list is accepted.
- `Verifier.RestoreStatusList` rebuilds the held list after a restart from the
  last raw list the relying party held (an older one lowers the floor):
  checked as `VerifyStatusList` checks it, and not dated after the given time,
  but however old (neither its age nor its `validUntil` is checked). Past its
  freshness a list is still the issuer's word on which entries were marked, so
  it is the floor a later list must keep; `VerifyBinding` takes it only while
  it is current, as any list. A list whose signing key has left the anchor is
  not restored (`ErrSignature`): the key may have left because it leaked, so
  its marks are not believed. Nothing is held then, and the next list is not
  compared with the marks seen before. The anchor decides which keys count.
  `ErrSignatureUnestablished` or a context error means restore again later;
  until then, verify no later list with no held list.
- `Verifier.VerifyBinding` checks, in order: the anchor's issuer signed it with
  an issuance key, under the W3C eddsa-jcs-2022 contract; it is well formed
  and carries no unsafe number; the time is within its period and the period
  is within the anchor's maximum; the held list is the issuer's, current, and
  does not mark it; it is for this relying party.

One spelling on the wire: times are UTC to the second, the list index is a
decimal string (never a JSON number, whose canonical form two values can
share), `roles` is always a list of distinct names, and the key is `keyId` and
a public JWK with exactly the members RFC 7638 hashes for its `kty` —
Ed25519, P-256 or RSA, a key the `crypto` validators accept.

A signature that cannot be checked now (the issuer's document unavailable) is
`ErrSignatureUnestablished`, not `ErrSignature`: retry, do not treat it as a
forgery.

Not here: what an issuer may bind (the kinds, roles and key classes in its
scope), and matching the key to a signature. Both are the caller's; `Binding`
carries what they need.
