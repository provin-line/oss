# `did:dplaax` DID method

`did:dplaax` は dPLaaX プロトコルの native DID method — credential 発行平面（`PipelinePassCredential` の issuer の背後にある owner / pipeline / process の identity）で認められる唯一の method である。本書は W3C DID Core の method 要件に沿って構成した method 仕様。実装は [`did/dplaax`](../../did/dplaax/)（grammar）と DID registry service にあり、本仕様と実装が乖離したらどちらかが誤りであり、同じ変更で直す。

**Status**: 本 method は今日 PoC registry が提供している。PoC であることは **registry セグメント**で表現され（例: `did:dplaax:poc.dplaax.dev:org:acme`）、method 名では決して表現されない — 識別子は PoC → production の移行を生き延びる。

## Method 名

`dplaax`。

## Method-specific identifier

### Syntax

```text
did:dplaax:{registry}:{accountType}:{accountId}[:{resourcePath…}]
```

- `{registry}` — 権威 registry の DNS 名（例: `poc.dplaax.dev`）。resolution URL はここから導出される。
- `{accountType}` — account 名前空間。現在サポートされるのは `org` のみ。
- `{accountId}` — registry 内の account 識別子。
- `{resourcePath…}` — 任意の colon 区切り resource セグメント。定義済みパターンは 2 つ:
  - Pipeline: `…:pipeline:{pipelineId}`
  - Process: `…:pipeline:{pipelineId}:process:{processId}`

全セグメントは **safe-segment 規則**（`[a-zA-Z0-9._-]+`、全 dot は不可）を満たさなければならない。この規則は DID 由来のセグメントが traversal リスクなしにストレージパスに参加できるようにするためで、違反は fail-closed に parse を落とす。

### エンコーディング・大文字小文字・正規化

- **Percent-encoding は拒否**する（正規化しない）: `%` は safe-segment のアルファベット外なので、エンコード済み識別子は parse に失敗する。
- **大文字小文字は保存**され、識別子のどこにも正規化は適用されない。registry セグメントへの帰結に注意: それは resolution の DNS 名として使われ、DNS は case-insensitive なので、`did:dplaax:Example.com:…` と `did:dplaax:example.com:…` は*同じ* host で解決される*別の* DID になる。registry と issuer は小文字の registry セグメントを使う**べき**であり、relying party は DID を byte 単位で比較し**なければならない**（case folding しない）。

### 割当と一意性

識別子が名指す registry が割当権威である:

- `{accountId}` は registry 内で一意 — 既存 id への異なる内容での owner 登録は拒否される（完全一致の再送は冪等な成功）。
- pipeline / process の id は親の下で一意 — 使用済み名前空間 slot への発行は拒否される。
- したがってグローバル一意性は registry 名の DNS 一意性に還元される。

## DID document

document は整合性保護された JSON: document の canonical（JCS）hash が、lifecycle イベントごとに registry の **append-only lifecycle log** に snapshot として記録される。document は round-trip で unknown member を保存するので、記録された hash は本実装がモデル化しない member にも commit する — registry は自身の log と乖離せずに document の状態を黙って差し替えることができない。

- **Verification method** — 2 つのエンコーディングを `type` で選択して読み、対応は**排他**: `Multikey` ↔ `publicKeyMultibase`（multibase base58btc `z`、multicodec `ed25519-pub` 0xed01 + 32 key bytes）、`JsonWebKey2020` ↔ `publicKeyJwk`。type が名指さないエンコーディングを運ぶ・両方を運ぶ・未知 type は拒否。この読み契約は凍結された credential wire の一部（CHANGELOG 参照）。本 registry が発行する document は JWK 形式を使い、Multikey は interop の読み経路。
- **鍵の役割** — 発行された pipeline/process document は 2 つの verification method を運ぶ: `#signing`（assertion — credential 発行）と `#auth`（authentication — L2 wireauth proof）。
- **Service** — document は subject ごとの service endpoint（`#vc-resolver`、`#audit`）を advertise できる。マッチングと導出規則は [protocol/services.ja.md](../protocol/services.ja.md) が規定する。

## 操作

| 操作 | 機構 | 認可 |
| --- | --- | --- |
| Create（owner） | `RegisterOwner` — 完全な**自己署名** document（proof が document 自身の鍵の支配を証明する） | L1 policy + document proof |
| Create（pipeline / process） | `IssuePipeline` / `IssueProcess`: registry が対象 DID に正確に bind された **owner 署名の delegation credential** を検証し、owner（process の場合は親 pipeline も）が active であることを要求し、`#auth`/`#signing` の鍵ペアを**生成**して document を組み立てる（`controller` = 構造上の親） | L1 policy + delegation 検証 |
| Read / Resolve | `ResolveDID` RPC（L1）または public resolution route（下記） | public route は open read |
| Update / key rotation | **未対応。** document 更新・鍵 rotation の操作は存在しない | — |
| Recovery | **未対応。** | — |
| Revoke | `UpdateStatus` — 受理される status は `revoked` のみ。不可逆かつ冪等で、`revoke` lifecycle event を追記する。revoked owner は pipeline/process を mint できず、revoked pipeline は process の親になれない | L1 policy（**request に controller 署名は載らない** — PDP が権威） |
| Deactivate（W3C の意味で） | そのようには公開していない — revocation が唯一の終端状態で、document を書き換えも非公開化もしない（下記） | — |

**revocation の発見は relying party の仕事である**: public resolution は lifecycle status を*参照せずに*保存された document を返す。liveness が必要な relying party は **lifecycle log**（`ReadLifecycleLog`）を読む: DID ごとの append-only な hash-snapshot イベント列で、イベント型は 2 つ — `register`（owner 登録も pipeline/process 発行も同じ型）と `revoke`。これは意図的な設計 — document は「何が登録されたか」の証拠、log は「それに何が起きたか」の証拠である。

## Resolution

document は識別子が名指す registry から HTTPS で解決される:

```text
https://{registry}/did/{accountType}/{accountId}[/{resourcePath…}]/did.json
```

path が運ぶのは registry の**後**のセグメント（registry は host が担う）。path セグメントは `/` で結合する。例:

```text
did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1
→ https://poc.dplaax.dev/did/org/acme/pipeline/p1/did.json
```

この route は意図的に**無認証**（W3C 式 open read）で、`application/did+json` を返し、malformed DID は 400、miss は 404。デプロイは registry ごとに `https://{registry}` base を override できる（split horizon、private network）— [deployment.ja.md](../architecture/deployment.ja.md) 参照。

### 応答の真正性

resolver の信頼連鎖は 3 本:

1. **Transport 権威** — DID が名指す registry host（または明示設定された override base）への HTTPS。
2. **Identity 検査** — resolver は返却 document の `id` が要求 DID に一致することを検証し**なければならない**（reference resolver は不一致を拒否する）。
3. **履歴整合** — document の JCS hash は append-only lifecycle log に snapshot されるので、registry による差し替えは log を読む誰にでも検出可能 — document をすり替える registry は自身の公開履歴と乖離する。

## Security / privacy considerations

- **操作の認証。** owner 作成は自己署名 document で鍵支配を証明する。発行は delegation credential で owner の意思を証明する。一方 revocation は L1 policy 層（registry 操作）で認可され、controller 署名によらない — デプロイの PDP policy は本 method の trust base の一部である。
- **Registry 侵害。** 侵害された registry は*新規* DID の捏造 document 提供や、revoke・サービス拒否ができる。しかし relying party が既に anchor した履歴を黙って書き換えることはできない — document hash は append-only lifecycle log にあり、乖離は検出可能。ただし読者ごとに異なる log を見せることは**できる**（PoC に cross-registry witnessing は無い）。log は tamper-*evident* であって tamper-*proof* ではない。
- **Replay / 改変 / 削除。** resolution 応答は freshness proof を運ばない。HTTPS を破れる network 攻撃者は古い（例: revocation 前の）document を replay しうる。より強い保証が要る relying party は独立チャネルで lifecycle log を照合する。
- **可用性。** 各 DID を提供する registry は 1 つ（単一権威、PoC 姿勢）。その不可用はその名前空間の resolution を停止させる。
- **鍵 rotation。** 未対応: 侵害された subject 鍵は rotate できない — subject を revoke して新しい DID を発行する。識別子のライフサイクルはそれを前提に設計すること。
- **相関と露出。** DID は組織構造（org → pipelines → processes）を公開し、service advertisement は endpoint URL を公開する。機微な名前を id に載せない。内部 endpoint を漏らしてはならない場所では split-horizon override を使う。

リポジトリ全体の脅威モデルと報告手順は SECURITY.md の scope であり、本節は method 固有の考慮のみを扱う。
