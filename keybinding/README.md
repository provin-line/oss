# keybinding — key bindings and revocation lists

A **key binding** is a credential in which an issuer states that a key belongs
to a subject — of a kind, with roles, of a key class — for one relying party,
for a period, with an entry in the issuer's revocation list. A relying party
verifies it against its trust anchor for the issuer and the issuer's
revocation list it already holds; it does not ask the issuer at decision time.

- `Issue` signs a `Binding` as a `KeyBindingCredential` (W3C VC Data Model 2.0,
  eddsa-jcs-2022). `IssueStatusList` signs the issuer's revocation list as a W3C
  `BitstringStatusListCredential`.
- `Verifier.VerifyStatusList` checks a list and returns it, current at the
  given time; a list never moves back (an older `validFrom`, or the same one
  with another body, is refused), a list dated in the future is not taken, and
  a list's id is a DID URL of its issuer. A `StatusList` cannot be changed once
  verified, and it counts only while its signing key is among the anchor's
  issuance keys. Keep the raw list and verify it again after a restart: with
  no held list, any current list is accepted.
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
