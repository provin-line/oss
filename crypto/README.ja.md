# crypto — 暗号プリミティブ
> 日本語版 — English: [README.md](README.md)

鍵生成・署名・検証のための最小限のインターフェースと Ed25519 実装、ES256 と RS256 の検証器。

## インターフェース

- `KeyGenerator` — `Generate() (*KeyPair, error)`、`Algorithm() string`
- `Signer` — `Sign(did, keyID string, data []byte) ([]byte, error)`
- `Verifier` — `Verify(publicKey, data, signature []byte) (bool, error)`

## 規約

- **`Signer` は意図的に DID を認識する**設計であり、生プリミティブではない: 本番環境のサイナーはレジストリの SignerService を呼び出す（KMS モデル — 秘密鍵はレジストリ外に出ない）。生鍵サイナーはテストおよび CLI ローカルのオーナーキー用にのみ存在する。
- `ed25519/` は署名のスイートである。`es256/`（ECDSA P-256 と SHA-256）と `rs256/`（RSASSA-PKCS1-v1_5 と SHA-256）は検証だけを行う。鍵と署名のバイト列は各 package が定める: ES256 は SEC1 の非圧縮の点と `r || s`、RS256 は 2048〜4096 ビットの PKCS #1 RSAPublicKey の DER。
- ECDSA の署名のバイト列は一意ではない（`(r, s)` が通れば `(r, n-s)` も通る）。署名をバイト列で数えたり重複を除いたりしない。
- 実装は下位ライブラリへの委譲前に不正な鍵・署名サイズを拒否する。
