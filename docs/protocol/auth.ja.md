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

## L2 — peer wire 証明（wireauth）

L2 の問い: *この名前の peer が本当にこの要求を送ったか？* internet-facing で組織間の面（`ChainPeerService`、`PayloadService`）を守る。これらは意図的に **L1 interceptor を持たない**: 異なる組織の peer は token 権威を共有しないので、信頼は要求そのものに載る必要がある。**L2 に auth-off モードは存在しない。**

各 RPC は、それが認証する要求への proof を運ぶ:

- 正確に `{signerDID, op, v, nonce, issuedAt, fields}` の canonical（JCS）view への **Ed25519 署名** — `v` は凍結された view version（現在 `1`。他の version は拒否）、`issuedAt` は秒精度の RFC 3339、`op` は RPC の view 判別子、`fields` はその business object。`op` と `fields` は verifier が**提供中の要求から**再構成する（proof からは決して読まない）。`signerDID` を署名 bytes に bind するので、鍵を共有する DID の alias が他 DID の署名を再利用することはできない。
- 署名者の鍵は **署名者の DID document 経由**で解決（`#auth` verification method）— cross-registry、事前共有鍵なし。
- **replay 防御**: acceptance window 内の single-use nonce（clock-skew 許容は非対称 — 過去向きが未来向きより大きい）+ **restart epoch barrier**（in-memory nonce store のリセットが restart 前の proof を再受理させない）。
- 順序付き検証: 構造チェック → 時刻境界 → 鍵解決 → 署名 → authorization → **最後に** nonce 記録。偽造が正規署名者の nonce を焼くことはできない。
- 任意の per-op **authorizer**（signer-to-actor policy）は署名検証の後にのみ走る — 未認証入力を見ることがない。

検証済みの relationship 変更（subscription 登録・切断）は加えて **relationship evidence** を残す: counterparty 署名済み要求と検証鍵素材を durable に保全し、relationship の存在を peer を信頼せずに後から証明できる（[audit-obligations.ja.md](../concepts/audit-obligations.ja.md)。rotation は [deployment.ja.md](../architecture/deployment.ja.md)）。

## L3 との関係

L1/L2 は transport の信頼、L3 — Data Integrity proof、content-addressed な chain link、transparency log、audit verdict — はデータの信頼。独立性の主張は正確に: **暗号学的 provenance 検証**（credential 署名・content hash・chain 構造）は L1/L2 が誠実だったことに依存しない。一方 L2 に*依存する*もの: peer 認可、relationship evidence、by-reference payload の可用性、そして「そのノードが audit しうるものをそもそも全部受け取れたか」という完全性。これらの面の脅威モデルは SECURITY.md の scope であり、本ページの scope ではない。
