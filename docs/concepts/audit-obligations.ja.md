# 監査記録義務
> 日本語版 — English: [audit-obligations.md](audit-obligations.md)

事後監査モデルは、当事者が編集も否認もできない記録の突合によって責任を帰属させる。本ページは **provin profile が義務づける記録・各記録の保持者・各義務の強制箇所**を集約する。義務は設計上、それを強制する各 seam に散在して記述されている — 本ページは索引であり、第二の SoT ではない。

## 3 つの記録義務

| 記録 | 内容 | 保持者 | 強制 seam |
|---|---|---|---|
| Emission ログ | publish した全イベント: credential hash + sequence number、append-only | Publisher | `pipeline/transport`（publisher ループ）、`tlog` 基盤上 |
| 購読記録 | subscriber の L2 署名済み `RegisterSubscription` ビュー（合意 payload 配送モードを含む） | **Publisher**（敵対側保有 — 記録は subscriber に不利に働く） | `network/.../chainmanager`（`store/`） |
| Ingress ストア | 検証済み ingress credential の保持 | Subscriber | `network/.../vcresolver` ストア（audit-reachable conformance class と対をなす） |

各記録は「その記録が*不利に働く側*が保持する」か append-only である — 「購読していない」「送っていない」「受け取っていない」のいずれの否認も、否認者が書き換えられない記録と突合できる。sequence number により emission の歯抜けは不具合ではなく証拠になる。emission の同一性は配送形態に依存しない（同じイベントは inline でも by-reference でも同じ記録になる）。

**保持期間**（監査期間）は deployment 義務 — profile が釘付けするのは「何を記録し、どう改竄検出可能にするか」であり、規制当局がどれだけの保持を求めるかは deployment の関心事。

## protocol の床と本義務の境界

dPLaaX protocol 自体が保証するのは監査の*床*: chain 位相、data-flow invariant、source commitment（audit-reachable class）、責任帰属規則（`audit.attribution.*` — 各 segment の issuer の Owner への帰属と、無条件の起点デフォルト）。これらは任意の準拠実装で成立する。

本ページの記録義務は意図的に **profile 層**に置かれている（2026-06-11 仕分け決定）: protocol に規範化すると、転送トポロジー不可知の wire spec に publisher/subscriber 語彙を輸入することになるため。第二実装が cross-implementation の監査 interop を必要とした時点で、「転送関係」抽象を protocol へ 0.x minor として追加するのが昇格パス。

## 基盤

3 記録はすべて `tlog` 上に永続化される — 組織ごとの append-only・改竄検出可能ログ。契約は実運用級（署名付き checkpoint、optional の inclusion/consistency proof）で実装は段階式。ネットワーク全体のログは存在しない — 各組織が自身の DID の下で自身の記録をホストする。
