# network/ — レジストリ & コーディネーションサーバー
> 日本語版 — English: [README.md](README.md)

dplaax ネットワークサービス。ノードバイナリ（`cmd/standalone`。パイプラインのデータプレーンも実行する）が ConnectRPC（h2c）を通じて公開する:

| Service | Responsibility |
|---|---|
| DIDService | `did:dplaax` ライフサイクル: オーナー登録、パイプライン/プロセスの発行、解決 |
| SignerService | KMS モデルの Ed25519 署名 — 秘密鍵はこのプロセス外に出ない |
| SchemaService | イミュータブルな追記専用スキーマレジストリ |
| ChainService | オペレーター向けパイプラインチェーン管理（サブスクライブ / 許可リスト） |
| ChainPeerService | インターネット向けの組織間ピアプロトコル（L2 ワイヤー署名済み） |
| VCResolverService | プロベナンスチェーンの VC ストレージと非同期クロスレジストリ解決 |

加えて、生 HTTP として W3C DID 解決（`GET /did/.../did.json`）と `GET /healthz` を提供する。

## 状態モデル: DB レス

すべての永続状態は設定可能なデータディレクトリ以下の plain ファイルとして管理する: コントロールプレーンのレコード（DID ドキュメント、鍵、スキーマ、サブスクリプション、許可リスト）は YAML、VC ストア（credential、resolution pool、audit queue、verdict — `vcresolver/filestore` + `auditor/filestore`）はファイルバックの evidence ディレクトリ。ノンスストアとインフラオペレーター状態はインメモリ（PoC 想定 — 再起動時の影響はサービスごとにドキュメント化済み）。ストレージはストアインターフェース越しに抽象化されており、ファイルを PostgreSQL に差し替えるのはフォークではなく Hub 側の置き換えで済む。

audit-reachable conformance class（ソースコミットメント — [pipeline/source](../pipeline/source/README.ja.md) 参照）で deploy する場合は、加えて **永続** VC ストアが必須となる: 遡及監査は発行からはるかに後で claim された source クレデンシャルを解決するためである。standalone ノードが配線するファイルバックのストアはこの保持義務を満たす（運用上のバックアップは別途必要）。インメモリストア（`vcresolver/memstore`）はテスト用スキャフォールドであり、満たすのは plain な PoC 想定のみである。

## 二層認証

- **L1（オペレーター向け）**: `pkg/auth` が検証する Bearer JWT（JWKS/Ed25519 または HS256）。プロトコル内で宣言されたリソース + アクションのポリシーオプションに対して RPC ごとに適用。
- **L2（ピア向け）**: ChainPeerService の全 RPC が `AuthProof` を持つ — JCS 正規化ビューに対する Ed25519 署名で、ノンスリプレイ保護と再起動エポックバリアを備える。`pkg/services/chainmanager/wireauth` に実装。**L2 に認証オフモードは存在しない。**

## レイアウト

```
cmd/standalone/   バイナリ: 設定ロード、DI ワイヤリング、マルチプレクサ登録
config/           application.conf（オペレーターレイヤー）
pkg/core/         マージ済み設定モデル、シークレット解決、SSRF 耐性 URL チェック
pkg/auth/         L1 JWT 検証 + 認可インターセプター
pkg/services/     サービスごとに 1 パッケージ — pkg/services/README.md 参照
```
