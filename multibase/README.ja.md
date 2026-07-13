# multibase — 自己記述バイト列エンコーディング

このリポジトリがワイヤに載せるバイト列のための multiformats
[multibase](https://github.com/multiformats/multibase) コーデック: Data Integrity の
`proofValue`（`vc` パッケージ）と Multikey の `publicKeyMultibase`（`did`
パッケージ）。いずれも base58btc（"z" プレフィックス）。

## API

- `EncodeBase58Btc(data []byte) string` — "z" + Bitcoin アルファベットの base58
- `DecodeBase58Btc(s string) ([]byte, error)` — "z" プレフィックスのない値は拒否

## 規約

- **プロデューサー／コンシューマー全員が共有する単一コーデック。** 独立した 2 つの
  base58 実装がエッジケース（典型は先頭ゼロバイト）で食い違うと、署名検証と鍵デコードが
  partition する — そのためコーデックはここで一度だけ凍結し、公式 W3C vc-di-eddsa の
  `proofValue` test vector にアンカーする。
- **デコードは fail-closed**: 別の multibase base（例: "f" hex）の値はエラーであり、
  base58 として誤デコードされることはない。
- ワイヤフォーマットが必要とした時点で追加の base はこのパッケージに加える。
  コンシューマーがエンコーディングを手書きすることはない。
