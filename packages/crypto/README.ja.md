# packages/crypto — 暗号プリミティブ
> 日本語版 — English: [README.md](README.md)

鍵生成・署名・検証のための最小限のインターフェースと Ed25519 実装。

## インターフェース

- `KeyGenerator` — `Generate() (*KeyPair, error)`、`Algorithm() string`
- `Signer` — `Sign(did, keyID string, data []byte) ([]byte, error)`
- `Verifier` — `Verify(publicKey, data, signature []byte) (bool, error)`

## 規約

- **`Signer` は意図的に DID を認識する**設計であり、生プリミティブではない: 本番環境のサイナーはレジストリの SignerService を呼び出す（KMS モデル — 秘密鍵はレジストリ外に出ない）。生鍵サイナーはテストおよび CLI ローカルのオーナーキー用にのみ存在する。
- `ed25519/` は PoC における唯一の実装である。P-256/P-384 は PoC 後の対応となるが、インターフェースにはすでにアルゴリズム次元が含まれているため、追加は非破壊的変更となる。
- 実装は下位ライブラリへの委譲前に不正な鍵・署名サイズを拒否する。
