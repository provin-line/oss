# packages/ — 共有ライブラリ層
> 日本語版 — English: [README.md](README.md)

`network/`・`pipeline/`・`cmd/` が利用する純粋なドメインライブラリ群。

## 層のルール

- **内部依存なし**: `packages/` 配下のコードは `gen/`・`network/`・`pipeline/`・`cmd/` をインポートしない。Protoで生成された型はここには登場しない。
- **一方向消費**: コンシューマが `packages/` に依存する。逆方向の依存は存在しない。
- ここで定義するインターフェースはシステムの安定したコントラクトである。この層の exported な識別子をリネームまたは形状変更することは、すべてのコンシューマに対する破壊的変更となる。

## パッケージマップ

| パッケージ | 責務 |
|---|---|
| `did/` | `did:dplaax` メソッド: パース・DID Document モデル・バリデーション・公開鍵抽出 |
| `canon/` | 署名スコープの正規化: JCS (RFC 8785)・URDNA2015・厳格な JSON デコード |
| `merkle/` | RFC 6962 Merkle ツリーコミットメント（`source_root`）|
| `vc/` | W3C VC Data Integrity: クレデンシャルモデル・ビルダー・検証器・暗号スイート・トラストポリシー |
| `crypto/` | 鍵生成・署名・検証インターフェース + Ed25519 実装 |
| `delegation/` | Pipeline/Process DID 向けのオーナー署名付き委任クレデンシャル |
| `resolver/` | DID Document 解決インターフェース + ローカル・grpc・マルチ実装 |
| `keystore/` | 秘密鍵ストレージコントラクト（KMS モデル境界） |
| `hoconconfig/` | 3 層 HOCON 設定ローダー |
| `orgverify/` | DNS ベースの組織アイデンティティ検証 |

`packages/` 内部の依存 DAG:

```
vc ──► did, canon, crypto, merkle
delegation ──► vc, did, crypto
resolver ──► did
orgverify ──► did, resolver
keystore ──► crypto
```
