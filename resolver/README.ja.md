# resolver — DID Document 解決
> 日本語版 — English: [README.md](README.md)

`Resolver` インターフェース（`Resolve(did string) (*did.DIDDocument, error)`）とその実装群。

## 実装

| パス | 動作 |
|---|---|
| `local/` | インメモリストア。テストおよびフィクスチャ用 |
| `grpc/` | レジストリの DIDService への ConnectRPC 呼び出し |
| `multi/` | ホームレジストリ優先、追加レジストリへのフォールバックあり |

## 規約

- `grpc/` は返されたドキュメントの ID がリクエストした DID と一致することを検証する（レジストリ置換攻撃への防御）。
- `multi/` のフォールバックは**接続エラー時のみ**発動する。いずれかのレジストリからのアプリケーションエラー（not-found・パーミッション）は信頼できる応答であり短絡する — フォールバックは否定パスの設定エラーを隠蔽してはならない。
- ホーム URL は DID の `registry` セグメントから導出される（`https://{registry}`）。デフォルトレジストリのエスケープハッチまたは明示的なセグメント→URL マップ（compose・マルチレジストリ開発環境）でオーバーライド可能。
