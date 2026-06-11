# didregistry — DID ライフサイクルサービス
> 日本語版 — English: [README.md](README.md)

`did:dplaax` のオーナー、パイプライン、プロセス DID を発行・管理する。

## ルール

- **すべての書き込みは暗号学的に権限を証明する。** オーナー登録は自己署名 Data Integrity プルーフを検証する（ブートストラップを解決 — 事前アカウント不要）; パイプライン/プロセスの発行では、さらにオーナー署名の委任クレデンシャル（`delegation`）を検証する。
- パイプライン/プロセスの発行時、サービスは `#auth-key` / `#signing-key` の Ed25519 ペアを生成し、`keystore` 経由で永続化する — 呼び出し元が秘密鍵を見ることはない。
- 発行された DID ドキュメントには設定からサービスエンドポイント（`#vc-resolver` など）が埋め込まれる。
- 鍵ローテーションのグレースセマンティクス: verify-grace は旧公開鍵を一定期間解決可能に保つ; 設計上 sign-grace は存在しない（KMS モデルは旧鍵による署名を即時停止する）。

## ストレージ

`store/` は DID ドキュメントストアインターフェースを定義し; `store/yamlstore/` は DID 階層を `{accountType}/{accountId}/pipelines/{id}/processes/{id}` というディレクトリツリーにマッピングし、レコードごとに YAML ファイルを持つ。秘密鍵はこのストアではなく `keystore` を通じて管理される。
