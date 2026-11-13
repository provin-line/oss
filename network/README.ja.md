# network/ — レジストリ & コーディネーションサーバー
> 日本語版 — English: [README.md](README.md)

dplaax ネットワークサービス。ネットワークノードバイナリ（`cmd/network`。コントロールプレーンのみ — データプレーンは別バイナリ `cmd/pipeline`）が ConnectRPC（h2c）を通じて公開する:

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

pipeline の永続 log は registry へミラーできる: pipeline はローカルの署名済み log をそのまま保持し、background の shipper が `MirrorLogSegment`（L1 + in-band wireauth）経由で checkpoint-aligned な segment を複製し、`GetMirrorState`（L1 read）が registry の durable mirror size を返す。registry はその検証済み prefix を custody・提供するだけで、決して再署名しない。shipper は今や `cmd/pipeline` に乗っている: そのバイナリは自分が開く永続 custody log すべて（emission・sink-receipt・sink-reject）を、それぞれの log 自身の checkpoint-signer identity として署名しながら ship し、ordered shutdown の最後に最終 flush を1回試みてから log ファイルを close する。まだミラーされていない terminal tail の record は flush interval の間 registry 側から見えず（lost）、ローカルボリュームを失った process は古い log の identity を引き継げず、新しい log identity へ切り替わる。

加えて、生 HTTP として W3C DID 解決（`GET /did/.../did.json`）、`GET /healthz`（liveness・static）、`GET /readyz`（readiness — 依存関係認識: evidence store、データプレーン稼働時の broker 接続、外部 PDP 到達性）を提供する。

## 状態モデル: DB レス

すべての永続状態は設定可能なデータディレクトリ以下の plain ファイルとして管理する: コントロールプレーンのレコード（DID ドキュメント、鍵、スキーマ、サブスクリプション、許可リスト）は YAML、VC ストア（credential、resolution pool、audit queue、verdict — `vcresolver/filestore` + `auditor/filestore`）はファイルバックの evidence ディレクトリ、保持した by-reference payload バイト列（`payloadresolver/filestore`）は専用のファイルバックストア、pipeline emission log の検証済み prefix はそれを custody するファイルバックの mirror ストア（`tlogservice/mirrorstore`）。ノンスストア、インフラオペレーター状態、そして publisher ごとの emit-health レポート（`chainmanager/emithealth`、TTL ベース）はインメモリ（PoC 想定 — 再起動時の影響はサービスごとにドキュメント化済み）。ストレージは seam 越しに抽象化されており、ファイルを PostgreSQL に差し替えるのはフォークではなく Hub 側の置き換えで済む。

VC ストアの seam は `vcresolver.VariantBackend` で、**意図的に意味論より下**に置いてある: backend は「名前の付いた bytes を置き、その名前が既に取られていたかを報告する」だけで、identity・canonical 検証・write-once 受入・body-only projection は、全 backend が背後に立つ `vcresolver.VariantStore` に 1 箇所だけ実装されている。したがって新しい substrate は 6 メソッドを実装すれば規則を継承し、規則を再約束する必要がない — そして 1 つ間違えて規則を弱めることもできない。backend が依然として負うのは storage にしか答えられないもの: atomic create、忠実な read-back、網羅的な listing。

audit-reachable conformance class（ソースコミットメント — [pipeline/source](../pipeline/source/README.ja.md) 参照）で deploy する場合は、加えて **永続** VC ストアが必須となる: 遡及監査は発行からはるかに後で claim された source クレデンシャルを解決するためである。`cmd/network` が配線するファイルバックのストアはこの保持義務を満たす（運用上のバックアップは別途必要）。インメモリストア（`vcresolver/memstore`）はテスト用スキャフォールドであり、満たすのは plain な PoC 想定のみである。

## 二層認証

- **L1（オペレーター向け）**: RPC ごとのポリシーオプション（リソース + アクション）を `pkg/auth` が強制する — 設定された policy-verifier（PDP）に対して o3co の認可インターセプターを配線する PEP。トークン発行とポリシー判定は外部（dPLaaX の `auth.provider` / `auth.policy-verifier` サービス）が担い、`pkg/auth` 自体はポリシーを決めず、トークンも発行しない。bearer JWT を検証するのは `cedar` backend の下だけで、その agent は何も認証しない（後述の「PDP backend と認証の所在」参照）。
- **L2（ピア向け）**: ChainPeerService の全 RPC が `AuthProof` を持つ — JCS 正規化ビューに対する Ed25519 署名で、ノンスリプレイ保護と再起動エポックバリアを備える。`pkg/wireauth` に実装。**L2 に認証オフモードは存在しない。** L2 は PDP から独立しており、policy-verifier を必要としない。
- **Evidence 書き込み**（`RegisterEvidence` / `RegisterAuditHead` / `RetainPayload` / `ReportEmitHealth`）: L1 + in-band wireauth — PDP ゲート（L1 のポリシーオプション）が「そもそも書き込みを許可するか」を判定し、リクエストはさらに wireauth `AuthProof` を運び、ハンドラーが in-band で検証する。証明された DID が authoritative。

### PDP backend と認証の所在

L1 認可は 3 者に分離されている: **トークン発行**（`auth.provider`）、**判定**（PDP）、**強制**（`pkg/auth`、ここではプロセス内）。ノードが依存するのは PDP だけで、`provin.network.auth.backend` で選ぶ — どの backend も fail-closed（必須の設定が欠けるとノードは起動しない）:

| backend | 判定点 | 呼び出し元を認証するか |
| --- | --- | --- |
| `o3co`（default） | 外部の o3co `auth.policy-verifier` | **する** — JWT を検証する |
| `opa` | 外部の Open Policy Agent | policy がトークンを確かめるならする |
| `cedar` | 外部の Cedar-agent | **する** — ノードが bearer JWT を検証し（`provin.network.auth.cedar.jwt.*`）、その `sub` を agent に問う |
| `static` | プロセス内の許可リスト | **しない** — bearer の*有無*だけを見て、有効性は見ない |

`cedar` には `cedar.jwt.issuer` と `cedar.jwt.audience`、そして鍵の供給元をちょうど 1 つ — `cedar.jwt.jwks-url`（https。非対称アルゴリズム）または `cedar.jwt.secret`（HS256。デコード後 32 バイト以上、`cedar.jwt.secret-encoding` で表記を指定: `utf8`（default）| `hex` | `base64`）— 指定する必要があり、満たさないとノードは起動しない。トークンが受理されるのは、`typ` が access token のもの（`at+jwt` または `application/at+jwt`、RFC 9068、大文字小文字は ASCII の範囲で不問）であり、署名が有効で、`exp` が失効しておらず、`iat` がノードの時計より先でなく、`nbf` が経過済みか存在せず（3 つとも 30 秒の猶予）、`iss` が設定と一致し、`aud` に設定した audience を含み、`sub` が空でないときだけである。

`jwks-url` を使うと、鍵集合は 10 分キャッシュされ、再取得は最短 30 秒間隔（トークンが未知の `kid` を名指したときも）。再取得が失敗している間は、期限切れの集合がそれが持つ `kid` のトークンをさらに 30 分検証し続けるため、発行者が撤回した鍵が JWKS の障害中に最大 40 分信頼されたままになりうる。未知の `kid` は拒否する。JWKS の障害（およびその他のトークン検査の失敗）は、クライアントには `Unavailable` ではなく `Unauthenticated`（push: 403、wire retry なし）として届く。Cedar endpoint がリゾルバーのエラーをすべて認証失敗に変えるためである。

loopback 以外の plaintext `http://` の PDP は、その `host:port` が `provin.network.auth.plain-internal`（default は空）に載っていない限り拒否される。載せた endpoint は private アドレスに解決されるときだけ到達される。だから、通過する通信の盗み見と改変から守られているネットワーク上の backend だけを載せること。不正な entry（`host:port` でない）や private でない IP リテラルは起動を失敗させ、ホスト名は接続のたびにアドレスを検査する。同じキーが `o3co`・`opa`・`cedar` に適用される。

PDP が答えられない（到達不能、timeout、HTTP 429/502/503/504）とき、L1 で守られた RPC は ConnectRPC `Unavailable`（"authorization backend unavailable"）で失敗し、もう `Internal` にはならない。PDP が不正な答えを返す（HTTP 500、body の不正）場合は `Internal` のままである。`Unavailable` はクライアントが retry してよい拒否である。

`static` は認可であって、**認証ではない**: perimeter がすでに認証している場合（単一テナント / dev）だけに使い、PDP が呼び出し元を識別すると期待される場所では使わない。設定のサーフェスは `pkg/auth/reference.conf` と backend ごとの godoc を参照。

認証付きのセルフホスト — 本物の `auth.provider` + 本物の policy-verifier + ノード + NATS を 1 コマンドで立て、record を `VERIFIED` の audit verdict まで進める — は [`deploy/quickstart/`](../deploy/quickstart/README.md) を参照。その README は **first-owner bootstrap**（`RegisterOwner` は L1 で守られているが、DID の grant には登録済みのオーナーが要る、という鶏と卵）と、本番向けの選択肢も扱う。

## レイアウト

```
cmd/network/      バイナリ: 設定ロード、DI ワイヤリング、マルチプレクサ登録
config/           application.conf（オペレーターレイヤー）
pkg/core/         マージ済み設定モデル、シークレット解決、SSRF 耐性 URL チェック
pkg/auth/         L1 PEP: 設定された PDP に対する認可インターセプター、cedar の bearer JWT の検証
pkg/wireauth/     L2 のワイヤー証明: 帯域内の AuthProof の署名と検証
pkg/services/     サービスごとに 1 パッケージ — pkg/services/README.md 参照
```
