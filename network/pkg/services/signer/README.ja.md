# signer — KMS モデル署名サービス
> 日本語版 — English: [README.md](README.md)

`packages/keystore` を基盤とした Ed25519 署名。秘密鍵はレジストリプロセス外に出ない; パイプラインコンポーネントとピアは鍵ではなく DID を保持する。

2 つの署名モード、2 つのコンシューマー:

| RPC | Input | Output | Used by |
|---|---|---|---|
| `Sign` | `sha256:<hex>` 事前ハッシュ | base58btc（`z`-マルチベース）署名 | VC プルーフ生成（パイプラインプロベナンス） |
| `SignRaw` | 生バイト | 生 64 バイト署名 | L2 ワイヤー署名（chainmanager wireauth） |

鍵の検索は DID + 論理鍵 ID（`auth` → `#auth-key`、`signing` → `#signing-key`）で行う。chainmanager はこのサービスに依存するが、コンシューマー側で定義した絞り込みインターフェースを通じて参照する — パッケージ自体には依存しない（サービス間のインポートサイクルを回避するため）。
