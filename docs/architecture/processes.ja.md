# Process peer カタログ

パイプラインは **Pipeline Process** のグラフ合成 — 4 つの peer 型があり、どれも特権的でない。normative な定義（peer 型の表と chain behaviour の **trigger rule**）は [pipeline/README.ja.md](../../pipeline/README.ja.md) が正本。本ページはアーキテクチャ視点 — 各型が*何のため*にあり、何を署名し、何を検証し、何を emit するか。デプロイ配線（ノードがどのループを走らせるか）は設定の領分 — [deployment.ja.md](deployment.ja.md) 参照。

## 共有機構

すべての process 型は同じ部品を合成する（`pipeline/contract` が公開コントラクト。外部 adapter はこれを実装する）:

- **Envelope** — wire 上の 1 イベント: 署名済み credential、payload bytes（stripped by-reference 形では無し）、producer の sequence number。
- **Chain behaviour** — `FirstDrop`（新しい chain の起点）または `ChainPreserving`（`previousCredential` = トリガーとなった predecessor の content hash）。**trigger rule** が決める — process の自称ではない。
- **Verification strategy** — 消費側 process は行動の前に *adjacent*（直前）credential を検証する。full-chain 検証は非同期 audit runner の仕事（[overview.ja.md](overview.ja.md)）。
- **Payload delivery** — inline（envelope 内）または by-reference（credential が宣言する `outputHash` で producer の serving boundary から dereference）。いずれでも **binding gate** — sha256(payload) が宣言 `outputHash` に一致 — が bytes と credential を結ぶ唯一の整合性チェック。
- **Emission log** — 各 producer は emit した sequence number ごとに append-only log へ 1 record を追記する。sequence の欠番は*調査すべき証拠*（POSSIBLE LOSS）であって自動的な改竄判定ではない。
- **Process observer** — fire-and-forget の事後通知（`contract.ProcessObserver`）。観測が pipeline の結果に影響することはない。

## Chained Process

Stateless な 1:1 変換 — statelessness は definitional。stateful な仕事は Source Process の領分。イベントごとに: adjacent credential を **fail-closed** で検証（Verified のみ進む — 寛容さは sink のもので、producing process には無い）→ ingress credential を保存（audit trail が変換に先行）→ payload 取得と binding → 変換（filter / converter step）→ chain-preserving で署名: 発行 credential は `previousCredential` = 消費 credential の content hash を運ぶ。filter されたイベントは静かに終端する（出力なし、observer では観測可能）。

## Source Process

**FirstDrop の発行**が唯一の definitional property: Source は chain を切り、新しい chain を始める。「ちょうど 1 つの Pipeline-conformant predecessor の到着」以外がトリガーなら、それは Source の emission — timer、window 満了、外部 push、poll（trigger rule。batch-of-1 規則と enrichment / boundary translation / aggregation の分類は pipeline/README.ja.md）。

reference mechanics は 2 種が in-repo:

- **Ingest** — Pipeline-conformant 入力はゼロ。push 実装ではイベントごとに 1 つの*外部*入力（`POST /ingest/{loop}/push`、PDP guard。readiness probe は public の `GET /ingest/{loop}/health`）。外部の生 record を、ループの process DID に帰属する FirstDrop として署名する。
- **Aggregate** — window/timer トリガーで N 個の pool 入力を fold する。各入力は **pool 前に** adjacent 検証（fail-closed drop: 未検証・未 binding・未保存のものは pool に届かない）。出力は消費した conformant set 全体への **source commitment** を運ぶ FirstDrop — audit 属性であって親リンクではなく、chain は厳密に線形のまま。audit 基盤が構成されていれば aggregate は emit locus で self-audit する: emit した head を broadcast 前に登録（store → receipt → audit queue）。

## Sink Process

in-network での chain の終端: 消費・検証し、payload を外界へ渡す（console と file の reference implementation が in-repo）。**sink kind** は verdict policy であり、寛容さは 1 つの kind の性質 — sink 一般の性質ではない:

| Kind | Verdict policy | 義務 |
| --- | --- | --- |
| `observation-only` | verdict に関わらず書く — 検査ツールは failed/indeterminate も観測して**よい** | 出力とともに verdict を記録する（検証されていないものが verified と読めてはならない） |
| `production` | fail-closed: Verified のみ書く | receipt 発行は MAY |
| `archival` | fail-closed: Verified のみ書く | receipt 発行は MUST、かつ全 reject が durable で hash-chain された reject log に残る |

receipt は sink 側の audit anchor: receipt を発行する sink は、任意の remote publish より前に各 receipt を local-first で登録する（store → tlog → audit queue）。

## Custom Process

任意の入出力形。少なくとも一方の I/O 側で `pipeline/contract` を実装することで表現する — 専用の runtime ディレクトリは無い。コントラクトそのものが拡張面だからである。vendor / ecosystem adapter（EDC、Kafka、SNS、…）は別リポジトリに住み、このコントラクトを安定に保つことが pipeline 層の第一の API 義務。custom バイナリが Source か chain-preserving な forwarder かは署名経路（FirstDrop か、`previousCredential` を運ぶか）で決まる — 名前では決まらない。
