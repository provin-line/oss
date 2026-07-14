# Service API 面

プロトコル定義（`api/protobuf/dplaax/*/v1`）が normative な RPC 契約 — per-RPC の request/response 形と認可 policy option はそこと生成コードにある。本ページは**責務と relying-party 契約**の正本: どの面が存在し、それぞれがどう認証され、consumer が何に依存してよいか。認証層そのものの仕様は [auth.ja.md](auth.ja.md)。

## standalone ノードの HTTP 面

以下はすべてノードの単一 listener（`provin.network.core.listen-addr`）上で提供される。gate 凡例: **L1** = bearer + PDP interceptor / **L2** = per-RPC wireauth proof / **PDP** = raw-HTTP route 上の L1 相当判定 / **public** = 意図的に無認証。

| 面 | Gate | 責務 |
| --- | --- | --- |
| `dplaax.schema.v1.SchemaService` | L1 | schema の登録・取得・deprecation（content-hash 参照の JSON Schema） |
| `dplaax.did.v1.DIDService` | L1 | `did:dplaax` lifecycle: owner 登録、pipeline/process 発行、解決、delegation 読み、revocation、lifecycle-log 読み |
| `dplaax.signer.v1.SignerService` | L1 | registry 保持鍵での署名（VC / raw）— registry が生成した鍵の DID 用 |
| `dplaax.vc.v1.VCResolverService` | L1 | content-addressed credential store: `StoreVC`、`ResolveVC`、successor 列挙 |
| `dplaax.audit.v1.AuditService` | L1 | per-head audit verdict（`GetAuditStatus` / `ListAuditStatuses`）と consumed-source receipt（`GetConsumedSources`） |
| `dplaax.tlog.v1.TlogService` | L1 | emission log の checkpoint と record 読み（transparency log の公開面） |
| `dplaax.chain.v1.ChainService` | L1 | operator 側 chain 管理: subscription、allow-list |
| `dplaax.chain.v1.ChainPeerService` | **L2** | internet-facing な peer 協調: publisher 情報、subscription 登録、切断 |
| `dplaax.payload.v1.PayloadService` | **L2** | internet-facing な by-reference payload 提供（`ResolvePayload`、streaming） |
| `GET /did/{accountType}/{accountId}[/{resourcePath…}]/did.json` | public | W3C 式 DID resolution（[did/method.ja.md](../did/method.ja.md)） |
| `POST /ingest/{loop}/push` | PDP | push 対応 source loop への HTTP ingest |
| `GET /ingest/{loop}/health` | public | loop 別 ingest readiness probe |
| `GET /healthz`, `GET /readyz` | public | liveness / readiness — [deployment.ja.md](../architecture/deployment.ja.md) 所有 |
| `GET /metrics` | public・**config gate（default off）** | OpenTelemetry counter。service handler 合成の**外**で mount — [deployment.ja.md](../architecture/deployment.ja.md) 所有 |

relying party が依存してよい構造的事実 2 つ:

- L2 の 2 面は **L1 interceptor を持たない** — その信頼は per-RPC wireauth proof であり、共有 token 権威なしに組織間で機能する（[auth.ja.md](auth.ja.md)）。
- `/metrics` は service 合成自身が mount することはなく、デプロイが有効化したときのみ存在する。

## サービス別の注記（consumer が依存してよいこと）

- **DIDService / resolution route** — RPC の `ResolveDID` は L1 gate。raw-HTTP route は同じ canonical document（`application/did+json`）を提供する open-read の W3C 式面。どちらも document を保存されたまま返す — **resolution は lifecycle status を参照しない**。revocation は lifecycle log から発見する（[did/method.ja.md](../did/method.ja.md)）。
- **VCResolverService** — content-addressed で immutable: 保存済み credential は content hash で取得できる。`ListSuccessors` はこの store が知る `previousCredential` リンクの逆引き。store は保持するものについてのみ答える — 不在はグローバルな非存在ではない。
- **AuditService** — verdict は *audit runner* の永続記録: linear-chain confidence と、（local receipt を持つ aggregate head には）独立の source-commitment verdict。verdict は「その locus で何が検査されたか」を名指すのであって、グローバルな真理の oracle ではない。
- **TlogService** — producer 側 emission log の署名付き checkpoint と record を提供。consumer は sequence カバレッジを配送と突合して loss の主張を bound する。
- **SignerService** — registry 保持鍵（発行した pipeline/process DID 用に registry が生成した鍵）でのみ署名する。owner 鍵は client 保持 — registry は決して見ない。
- **ChainPeerService / PayloadService** — 組織間 seam。登録/切断は永続的な relationship 状態を変更し、counterparty 署名付き relationship evidence を残す。payload 提供は毎 fetch で allow-list admission を強制する。

## Service advertisement と endpoint 導出

**provin v0 profile に対して normative。** これらは operational な routing 規則であり、0.x 中は CHANGELOG 付きで進化しうる。**凍結された credential wire の一部ではない**（CHANGELOG の「v0 credential wire freeze declaration」参照）。

`did:dplaax` document は subject ごとの service endpoint を advertise できる:

| Fragment | `type` | 内容 |
| --- | --- | --- |
| `#vc-resolver` | `VCResolver` | この subject の発行 credential が解決できる場所（VCResolverService base URL） |
| `#audit` | `AuditService` | この subject の emission に対する audit verdict / receipt の提供場所 |

**マッチング規則（全 consumer 共有）**: service entry は、`type` が一致し**かつ** `id` が fragment そのもの（`#vc-resolver` / `#audit`）または `{subjectDID}{fragment}` に**完全一致**するときだけマッチする。fragment で*終わるだけ*の別 URI は他者の識別子 — capture としても ambiguity としても数えない。2 件以上のマッチ: **error**（ambiguity は fail-closed）。ちょうど 1 件で endpoint が空: **error**（存在する advertisement は使えなければならない — 黙って fallback しない）。

**consumer 別の導出順:**

- **Bundle export（`provin bundle export`）** — credential: `--vc-resolver-base <registry>=<url>` override → advertisement（**必須**: 0 件は error）。audit receipt: `--audit-base <registry>=<url>` override → advertisement → legacy fallback（`--did-base` map、無ければ `https://{registry}`）。非対称は意図的: receipt routing は advertisement より古く、advertisement 以前に発行された document も export し続けられなければならない。
- **Batch chain assembly（node 内の predecessor 解決）** — 消費 credential の upstream hint が先。issuer の `#vc-resolver` advertisement（exactly-one 必須。CLI override も registry fallback も無い）へ進むのは**接続エラーのみ**。hint 先の store が NotFound を*答えた*場合は miss — entry は retry され、reroute されない。解決不能な issuer の hole は queue に残り、audit runner が bound する。

override は **split-horizon の seam**: advertised URL は emitting network 内で canonical であり、外からは到達不能でありうる（quickstart は `http://node:8443` を advertise し、host で走る CLI は `--vc-resolver-base` / `--audit-base` で `http://localhost:8443` に override する）。

## 凍結境界

**credential Data Integrity wire**（context、proof algorithm、canonicalization、source-commitment 形、verification-method 読み契約）は凍結済みでテストが強制する — CHANGELOG 参照。本ページの内容 — RPC 面、routing、導出順、metric 名 — はすべて **operational surface**: 安定名だが、0.x 中は CHANGELOG 付きで変更可能。
