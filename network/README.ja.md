# network/ — レジストリ & コーディネーションサーバー
> 日本語版 — English: [README.md](README.md)

dplaax ネットワークサービス。ノードバイナリ（`cmd/standalone`。パイプラインのデータプレーンも実行する）が ConnectRPC（h2c）を通じて公開する:

| Service | Responsibility |
|---|---|
| DIDService | `did:dplaax` ライフサイクル: オーナー登録、パイプライン/プロセスの発行、解決 |
| SignerService | KMS モデルの Ed25519 署名 — 秘密鍵はこのプロセス外に出ない |
| SchemaService | イミュータブルな追記専用スキーマレジストリ |
| ChainService | オペレーター向けパイプラインチェーン管理（サブスクライブ / 許可リスト / publisher の emit-health レポート） |
| ChainPeerService | インターネット向けの組織間ピアプロトコル（L2 ワイヤー署名済み） |
| VCResolverService | プロベナンスチェーンの VC ストレージと非同期クロスレジストリ解決 |
| AuditService | 非同期 chain-auditor の読み取りサーフェス（verdict、consumed-source receipt）と evidence 登録 |
| TlogService | emission log の checkpoint / record 読み。`MirrorLogSegment` は checkpoint-aligned segment を registry の custody へ送る（L1 + in-band wireauth）。`GetMirrorState` は registry の durable mirror size を読む（L1 read、`tlog:read`） |
| PayloadStoreService | by-reference payload delivery の書き込み側 — 後続の解決のために payload バイト列を deposit する |

pipeline の永続 log は registry へミラーできる: pipeline はローカルの署名済み log をそのまま保持し、background の shipper が `MirrorLogSegment`（L1 + in-band wireauth）経由で checkpoint-aligned な segment を複製し、`GetMirrorState`（L1 read）が registry の durable mirror size を返す。registry はその検証済み prefix を custody・提供するだけで、決して再署名しない。shipper は今や `cmd/pipeline` に乗っている: そのバイナリは自分が開く永続 custody log すべて（emission・sink-receipt・sink-reject）を、それぞれの log 自身の checkpoint-signer identity として署名しながら ship し、ordered shutdown の最後に最終 flush を1回試みてから log ファイルを close する。`cmd/standalone` は今も ship しない — そちらの TlogService 読み取りは引き続き in-process map から返り、何もミラーしない。まだミラーされていない terminal tail の record は flush interval の間 registry 側から見えず（lost）、ローカルボリュームを失った process は古い log の identity を引き継げず、新しい log identity へ切り替わる。

加えて、生 HTTP として W3C DID 解決（`GET /did/.../did.json`）、`GET /healthz`（liveness・static）、`GET /readyz`（readiness — 依存関係認識: evidence store、データプレーン稼働時の broker 接続、外部 PDP 到達性）を提供する。

## 状態モデル: DB レス

すべての永続状態は設定可能なデータディレクトリ以下の plain ファイルとして管理する: コントロールプレーンのレコード（DID ドキュメント、鍵、スキーマ、サブスクリプション、許可リスト）は YAML、VC ストア（credential、resolution pool、audit queue、verdict — `vcresolver/filestore` + `auditor/filestore`）はファイルバックの evidence ディレクトリ、保持した by-reference payload バイト列（`payloadresolver/filestore`）も専用のファイルバックストアを持つ。ノンスストア、インフラオペレーター状態、そして publisher ごとの emit-health レポート（`chainmanager/emithealth`、TTL ベース）はインメモリ（PoC 想定 — 再起動時の影響はサービスごとにドキュメント化済み）。ストレージは seam 越しに抽象化されており、ファイルを PostgreSQL に差し替えるのはフォークではなく Hub 側の置き換えで済む。

VC ストアの seam は `vcresolver.VariantBackend` で、**意図的に意味論より下**に置いてある: backend は「名前の付いた bytes を置き、その名前が既に取られていたかを報告する」だけで、identity・canonical 検証・write-once 受入・body-only projection は、全 backend が背後に立つ `vcresolver.VariantStore` に 1 箇所だけ実装されている。（保持した by-reference payload バイト列 `payloadresolver/filestore` に加え、pipeline emission log の検証済み prefix を custody するファイルバックの mirror ストア `tlogservice/mirrorstore` も同様の構図。）したがって新しい substrate は 6 メソッドを実装すれば規則を継承し、規則を再約束する必要がない — そして 1 つ間違えて規則を弱めることもできない。backend が依然として負うのは storage にしか答えられないもの: atomic create、忠実な read-back、網羅的な listing。

audit-reachable conformance class（ソースコミットメント — [pipeline/source](../pipeline/source/README.ja.md) 参照）で deploy する場合は、加えて **永続** VC ストアが必須となる: 遡及監査は発行からはるかに後で claim された source クレデンシャルを解決するためである。standalone ノードが配線するファイルバックのストアはこの保持義務を満たす（運用上のバックアップは別途必要）。インメモリストア（`vcresolver/memstore`）はテスト用スキャフォールドであり、満たすのは plain な PoC 想定のみである。

## 二層認証

- **L1（オペレーター向け）**: `pkg/auth` が検証する Bearer JWT（JWKS/Ed25519 または HS256）。プロトコル内で宣言されたリソース + アクションのポリシーオプションに対して RPC ごとに適用。
- **L2（ピア向け）**: ChainPeerService の全 RPC が `AuthProof` を持つ — JCS 正規化ビューに対する Ed25519 署名で、ノンスリプレイ保護と再起動エポックバリアを備える。`pkg/services/chainmanager/wireauth` に実装。**L2 に認証オフモードは存在しない。**
- **Evidence 書き込み**（`RegisterEvidence` / `RegisterAuditHead` / `RetainPayload` / `ReportEmitHealth`）: L1 + in-band wireauth — PDP ゲート（L1 のポリシーオプション）が「そもそも書き込みを許可するか」を判定し、リクエストはさらに wireauth `AuthProof` を運び、ハンドラーが in-band で検証する。証明された DID が authoritative。

## レイアウト

```
cmd/standalone/   バイナリ: 設定ロード、DI ワイヤリング、マルチプレクサ登録
config/           application.conf（オペレーターレイヤー）
pkg/core/         マージ済み設定モデル、シークレット解決、SSRF 耐性 URL チェック
pkg/auth/         L1 JWT 検証 + 認可インターセプター
pkg/services/     サービスごとに 1 パッケージ — pkg/services/README.md 参照
```
