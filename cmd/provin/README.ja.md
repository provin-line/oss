# cmd/provin — オペレーター CLI
> 日本語版 — English: [README.md](README.md)

`provin` CLI: dplaax レジストリに対する DID・スキーマ・チェーン管理のためのオペレーターツール。

## サーフェス

| コマンドグループ | 操作 | バックエンド | 状態 |
| --- | --- | --- | --- |
| `owner` | init（ローカル鍵生成 + 自己署名登録） | DIDService | 実装済み |
| `pipeline` | create（委任署名による発行） | DIDService | 実装済み |
| `process` | create（委任署名による発行） | DIDService | 実装済み |
| `bundle` | export（チェーン + authority document のアーカイブ）、verify（オフライン再検証・ネットワーク不要） | VCResolverService + DID 解決（export）; なし（verify） | 実装済み |
| `schema` | register | SchemaService | 実装済み |
| `chain` | subscribe, set-allow | ChainService | 実装済み |
| `org` | verify / inspect / diagnose / generate-txt | DNS + DID 解決（レジストリへの変更なし） | 実装済み |

グローバルフラグ: `--registry`（環境変数 `PROVIN_REGISTRY`）、`--token`（環境変数 `PROVIN_TOKEN`）。
`org` グループは `--registry` のみを取る — DID 解決は認証不要の公開 route のため、
`--token` は不要かつ受け付けない。

```console
$ provin owner init --did did:dplaax:poc.dplaax.dev:org:acme --key acme-owner.jwk \
    --registry https://poc.dplaax.dev --token $PROVIN_TOKEN
registered owner did:dplaax:poc.dplaax.dev:org:acme (key: acme-owner.jwk)

$ provin pipeline create --did did:dplaax:poc.dplaax.dev:org:acme:pipeline:lot \
    --owner-key acme-owner.jwk
issued pipeline did:dplaax:poc.dplaax.dev:org:acme:pipeline:lot (signing keys held by the registry)

$ provin org verify --did did:dplaax:poc.dplaax.dev:org:acme.com --registry https://poc.dplaax.dev
endorsement: verified
```

`owner init` は custody-first でリトライ可能: オーナーの JWK ファイル（0600、
create-only、`kid` がオーナー DID を持つ）はレジストリが DID を知る前にディスクに
書かれ、再実行時は `kid` が `--did` に一致する既存の鍵ファイルを再利用する。

## 規約

- `internal/client/` — ConnectRPC クライアントの構築 + ベアラートークンインターセプター（wire のみ）。`internal/commands/` — コマンドグループごとに 1 ファイル; リクエスト成形と proto ↔ ドメイン変換はコマンド側が持つ。`internal/keyfile/` — CLI ローカルのオーナー鍵管理（RFC 8037 OKP JWK）。
- オーナーの秘密鍵はローカルで生成され、JWK ファイルとして保存される。これがレジストリ外に存在する唯一の秘密鍵（その他はすべて KMS モデル）。
- 終了コードはスクリプト利用を考慮した意味を持つ。`org verify` は endorsement 判定結果をプロセス終了コードにマッピングする: `verified`=0、`missing`=1、`invalid`=2、`unreachable`=3、`na`=4。
  `org inspect` / `org diagnose` / `org generate-txt` は判定スコアを持たない — 実行が成功すれば状態に関わらず終了コード 0（inspect/diagnose は状態を標準出力に出す）。判定結果の分類は `orgverify/README.md` を参照。
