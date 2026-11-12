# Auth 層（L1 / L2）

RPC 面は 2 つの認証層が守り、3 層目 — provenance chain そのもの — がデータの信頼を運ぶ。各層は異なる問いに答え、どの層も他層の代替にならない（[overview — 信頼層](../architecture/overview.ja.md)）。本ページはプロトコル視点: 各層が何を証明し、デプロイが何を用意すべきか。enforcement のカタログ（interceptor 配線、config key、backend 別挙動）は [network/README.ja.md](../../network/README.ja.md) と [network/pkg/auth](../../network/pkg/auth/README.ja.md) が所有する。

## L1 — API アクセス（bearer + PDP）

L1 の問い: *この呼び出し元はこの RPC を呼んでよいか？* 3 者分離で構成される:

| 役割 | コンポーネント | 備考 |
| --- | --- | --- |
| Token 発行（authN） | 外部 `auth.provider` | DID-grant OAuth。identity JWT（`sub` = owner DID）を発行 |
| 判定（authZ） | 外部 PDP | backend は差し替え可能: `o3co`（default）\| `opa` \| `cedar` \| `static` |
| 強制（PEP） | in-process interceptor | per-RPC policy option（`resource` + `action`）を読み、PDP に問い、allow/deny |

デプロイが内面化すべき事実:

- **policy は proto に per-RPC で宣言される**（`o3co.authz.v1.policy` method option）。descriptor test が「保護対象サービスは全 RPC に注釈を持つ」ことを assert する — 無防備な RPC は perimeter でなくビルドが落ちる。
- **認証の所在は backend で変わる。** `o3co` は JWT を検証する。`static` は bearer の*存在*しか見ない — それは authorization の allow-list であって **authentication ではない**。`static` は perimeter が既に認証している場所でのみ使う。backend 表は network/README.ja.md。
- **boot で fail-closed**: 外部 backend（`o3co` / `opa` / `cedar`）では PDP URL の欠落や scheme 無しは boot error であり、開いたままのサーバにはならない。`static` は意図的に PDP URL を要しない — allow-list は in-process で、空の allow-list は deny-all。
- **PDP への平文呼び出しは明示の許可制**: loopback 以外への `http://` は、そのエンドポイントの `host:port` を `provin.network.auth.plain-internal`（既定は空）に列挙しない限り拒否される。列挙したエンドポイントは private address に解決される場合にのみ到達する。
- **`cedar` はノード内で呼び出し側の JWT を検証する**: Cedar agent は何も認証しないため、`provin.network.auth.cedar.jwt.*`（issuer、audience、`jwks-url` / `secret` のちょうど一方）が必須で、agent に問い合わせる principal は検証済みトークンの `sub`（空は不可）。トークンの `typ` は RFC 9068 が access token に与えるもの、`at+jwt` か `application/at+jwt`（ASCII の大文字・小文字は問わない）でなければならず、`exp` と `iat` を持ち、`iat` はノードの時計より 30 秒の leeway を超えて先であってはならない。RFC 9068 が挙げるほかの claim（`jti`、`client_id` など）は要しない。トークンは綴りが 1 つに決まる compact JWS でなければならず、claims はリポジトリの厳しい JSON の規則（重複するキーがない、正しい Unicode、1 つの object の中に大文字・小文字だけ違うキーがない）で読む。JWKS は 10 分キャッシュし、refetch は最短 30 秒間隔。refetch が失敗している間は、期限切れの集合が既知の `kid` をさらに 30 分検証するため、撤回された鍵は JWKS 停止中に最大 40 分信頼されうる（未知の `kid` は拒否）。
- **PDP の停止は `Unavailable`（呼び出し側の拒否ではない）**: PDP が答えられない（到達不能、timeout、HTTP 429/502/503/504）とき、L1 で守られた RPC は ConnectRPC の `Unavailable`（従来は `Internal`）で失敗し、pipeline の push endpoint（`/ingest/<name>/…`）は **`Retry-After` 付きの 503**（従来は 403）を返す。PDP が不正な応答をした場合（HTTP 500、body 不正）は従来どおり `Internal` / 403。`cedar` backend は例外で、トークンの検証失敗（JWKS の停止を含む）は `Unauthenticated`（push は 403、wire retry なし）になる。Cedar endpoint が resolver のエラーをすべて認証失敗にするため。呼び出し側は `Unavailable` を backoff 付きで retry してよい。pipeline の wire retry も、L1 で守られた RPC を PDP の停止中に bounded な budget の範囲で retry するようになった。

## L2 — peer wire 証明（wireauth）

L2 の問い: *この名前の peer が本当にこの要求を送ったか？* internet-facing で組織間の面（`ChainPeerService`、`PayloadService`）を守る。これらは意図的に **L1 interceptor を持たない**: 異なる組織の peer は token 権威を共有しないので、信頼は要求そのものに載る必要がある。**L2 に auth-off モードは存在しない。**

各 RPC は、それが認証する要求への proof を運ぶ:

- 正確に `{signerDID, aud, op, v, nonce, issuedAt, fields}` の canonical（JCS）view への **Ed25519 署名** — `v` は view version（現在 `2`。proof も `view_version` として持つ）、`aud` は **audience**（要求の送り先の node の registry ID）、`issuedAt` は秒精度の RFC 3339、`op` は RPC の view 判別子、`fields` はその business object。`op` と `fields` は verifier が**提供中の要求から**再構成する（proof からは決して読まない）。`signerDID` を署名 bytes に bind するので、鍵を共有する DID の alias が他 DID の署名を再利用することはできない。`aud` を bind するので、ある node 向けの proof は別の node では検証に通らない。
- **view version を最初に確かめる**: node の verifier は、設定された version（既定は今の version）だけを受理し、audience を束ねない version 1 は決して受理しない。それ以外の version は署名者を解決する前に断り、view は proof の version で組み直す。
- **次に audience を確かめる**: node の verifier は、audience が自分の `provin.network.registry.id` と完全に一致する proof だけを受理する。この照合は構造チェックと一緒に、署名者を解決する前に行い、view は自分の registry ID で組み直す。そのため別の node 向けの proof はそこで nonce を消費せず、書き換えた audience は署名で落ちる。照合は要求の URL も `Host` も使わないので、proxy の後ろや別名の node でも同じに確かめる。
- 署名者の鍵は **署名者の DID document 経由**で解決（`#auth` verification method）— cross-registry、事前共有鍵なし。
- **replay 防御**: acceptance window 内の single-use nonce（clock-skew 許容は非対称 — 過去向きが未来向きより大きい）+ **restart epoch barrier**（in-memory nonce store のリセットが restart 前の proof を再受理させない）。boot window 中はこの barrier が正当な fresh proof も拒否するが、handler は permanent な `Unauthenticated` ではなく **retryable な `Unavailable`** を返し、conforming peer は bounded な再署名 retry で回復する。retry budget 枯渇時（または budget を超える clock skew の peer）は racing call が drop される — post-v0 の durable nonce store で閉じる、PoC posture の許容された残存 loss。
- 順序付き検証: 構造チェック（view version と audience を含む）→ 時刻境界 → 鍵解決 → 署名 → authorization → **最後に** nonce 記録。偽造も、別の node 向けや別の view version の proof も、正規署名者の nonce を焼くことはできない。nonce store は、proof の期限の後に届いた nonce を断る。
- 任意の per-op **authorizer**（signer-to-actor policy）は署名検証の後にのみ走る — 未認証入力を見ることがない。

proof の形は 4 つの設計判断で決まっている。code とその試験はこの名前で参照する:

- **D-w1 — view は署名者の DID を覆う。** 2 つの DID が同じ `#auth` 鍵を載せることがある（alias、または他者の鍵を載せた DID document）。`signerDID` が署名 bytes に入るので、一方として署名した proof は他方としては検証に通らない（unknown-key-share への防御）。
- **D-w10 — nonce は署名者ごとに記録する。** nonce store の鍵は `(signerDID, nonce)`。nonce は署名者に対してだけ意味を持つ。同じ nonce を使う 2 人の署名者はぶつからず、ある署名者が他の署名者の nonce を先に使って消費することもできない。
- **D-w11 — fields の値は string、boolean、`null` と、それらの object と array だけ。** 数は decimal の string で運ぶ。同じ値の Go の `int` と `float64` は別の bytes に canonical 化され、JCS の数の直列化は凍結された組織間の wire で相互運用の危険になる。数を持たない fields の bytes の形は 1 つに決まる。
- **D-w12 — view は audience を覆う。** proof は、それが向かう node をその registry ID で名指し、view がそれを束ねる。ある node が受け取った proof は、別の registry の node では検証に通らない。送り手は endpoint と同じ出所から audience を得る:
  - pipeline の自 node（`vc-store-endpoint`）: そこへ送る proof のすべてに 1 つの audience を起動時に決める。proof の署名に使う DID のすべてに共通の registry segment（pipeline は自分の registry の node に publish する）。署名者が 2 つの registry にまたがるときは、`node-registry` で node の registry を名指さない限り起動しない。
  - by-reference の上流（loop の `upstream-endpoint`）: loop の上流の pipeline DID（`ingress-subject`、または aggregate の ingress の `subject`）の registry segment（その node がその pipeline の payload を持つ）。
  - publisher の `#chain-manager` endpoint: publisher の DID の registry segment（その registry が DID document にその endpoint を載せる）。registry の `#chain-manager` endpoint は、その registry の node が受ける。

  DID の registry segment が、その node の audience である（`wireauth.AudienceForDID`）。その endpoint の node が別の registry のものなら、`node-registry` と `upstream-registry` で registry を名指す。endpoint と audience を組にするのは送り手で、wire 証明はその組を認証しない。endpoint を誤った node に向けると、その node に、組の相手の node が新しいうちは受理する proof を渡すことになる（[deployment.ja.md](../architecture/deployment.ja.md)）。

D-w1、D-w10、D-w12 と、nonce は署名が通った後にだけ記録されることは、Dolev-Yao の攻撃者に対して Tamarin の model `verification/tamarin/wireauth.spthy` で確かめている（[verification/README.ja.md](../../verification/README.ja.md)）。

nonce の一度きりは **verifier ごと**。1 つの audience を持ち、それぞれ自分の nonce store を持つ 2 つの verifier は、同じ proof をそれぞれ 1 回ずつ受理しうる。そのため、1 つの registry の L2 の面は **1 つの network process** が受ける（[deployment.ja.md](../architecture/deployment.ja.md)）。

検証済みの relationship 変更（subscription 登録・切断）は加えて **relationship evidence** を残す: counterparty 署名済み要求、その audience、検証した view version と検証鍵素材を durable に保全し、relationship の存在を peer を信頼せずに後から証明できる（[audit-obligations.ja.md](../concepts/audit-obligations.ja.md)。rotation は [deployment.ja.md](../architecture/deployment.ja.md)）。view version `1` の記録（view が audience を束ねる前に書かれたもの）は audience を持たず、version 1 の view `{signerDID, op, v, nonce, issuedAt, fields}` で再検証する。

## L3 との関係

L1/L2 は transport の信頼、L3 — Data Integrity proof、content-addressed な chain link、transparency log、audit verdict — はデータの信頼。独立性の主張は正確に: **暗号学的 provenance 検証**（credential 署名・content hash・chain 構造）は L1/L2 が誠実だったことに依存しない。一方 L2 に*依存する*もの: peer 認可、relationship evidence、by-reference payload の可用性、そして「そのノードが audit しうるものをそもそも全部受け取れたか」という完全性。これらの面の脅威モデルは SECURITY.md の scope であり、本ページの scope ではない。
