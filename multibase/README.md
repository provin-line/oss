# multibase — Self-Describing Byte-String Encoding

The multiformats [multibase](https://github.com/multiformats/multibase) codec for
the byte strings this repository puts on the wire: Data Integrity `proofValue`
(package `vc`) and Multikey `publicKeyMultibase` (package `did`), both base58btc
("z" prefix).

## API

- `EncodeBase58Btc(data []byte) string` — "z" + Bitcoin-alphabet base58
- `DecodeBase58Btc(s string) ([]byte, error)` — rejects any value without the
  "z" prefix

## Conventions

- **One codec, shared by every producer and consumer.** Two independent base58
  implementations diverging on an edge case (leading zeros are the classic one)
  would partition signature verification from key decoding — so the codec is
  frozen here once, anchored to the official W3C vc-di-eddsa `proofValue` test
  vector.
- **Decoding is fail-closed**: a value in another multibase base (e.g. "f" hex)
  is an error, never mis-decoded under base58.
- Additional bases join this package when a wire format needs them; consumers
  never hand-roll an encoding.
