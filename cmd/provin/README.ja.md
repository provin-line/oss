# cmd/provin — オペレーター CLI
> 日本語版 — English: [README.md](README.md)

`provin` CLI: dplaax レジストリに対する DID・スキーマ・チェーン管理のためのオペレーターツール。

## サーフェス（予定）

| コマンドグループ | 操作 | バックエンド |
|---|---|---|
| `owner` | init（ローカル鍵生成 + 自己署名登録） | DIDService |
| `pipeline` | create（委任署名による発行） | DIDService |
| `process` | create（委任署名による発行） | DIDService |
| `schema` | register | SchemaService |
| `chain` | subscribe, set-allow | ChainService |
| `org` | verify / inspect / diagnose / generate-txt | DNS + DID 解決（レジストリへの変更なし） |

グローバルフラグ: `--registry`（環境変数 `PROVIN_REGISTRY`）、`--token`（環境変数 `PROVIN_TOKEN`）。

## 規約

- `internal/client/` — ConnectRPC クライアントの構築 + ベアラートークンインターセプター + proto ↔ ドメイン変換。`internal/commands/` — コマンドグループごとに 1 ファイル; コマンドはリクエスト成形以外のプロトコルロジックを持たない。
- オーナーの秘密鍵はローカルで生成され、JWK ファイルとして保存される。これがレジストリ外に存在する唯一の秘密鍵（その他はすべて KMS モデル）。
- 終了コードはスクリプト利用を考慮した意味を持つ（`org verify` は判定レベルをコードにマッピングする）。
