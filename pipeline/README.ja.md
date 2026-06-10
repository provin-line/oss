# pipeline/ — Pipeline コンポーネント ピアカタログ
> 日本語版 — English: [README.md](README.md)

パイプラインは **Pipeline コンポーネントのグラフ合成**である。プロトコルは4種類のピアコンポーネント型を定義しており、どの型も特権を持たない。「コア」型も「アウター」型も存在しない。

| 型 | パイプライン準拠入力 | 出力 | VCチェーンの振る舞い | 定義的性質 |
|---|---|---|---|---|
| **FilterConvert** | 1 | 1（フィルタ時は0） | チェーンを保持する（`previousCredential`） | ステートレスな1:1変換 |
| **Origin Source** | N ≥ 0（自由） | 1 | **チェーンを切断 — 新たな FirstDrop を発行** | FirstDrop 発行が*唯一の*定義的性質 |
| **External Sink** | 1（またはN） | 0（外部世界） | チェーンはネットワーク内で終端 | — |
| **Custom** | 任意 | 任意 | 任意 | 1つ以上のI/O側で Pipeline Contract に準拠 |

ステートフルなワークロード（aggregate / join / window）は Origin Source に属する。ステートレス性が定義的性質である FilterConvert には属さない。

## チェーン挙動の判定基準 — トリガー規則（provin wire profile、規範）

境界の出力が**チェーン保持**になるのは、その実行が **Pipeline-conformant な前イベント 1 件の到着によって起動された場合に限る**（`previousCredential` = そのイベントのクレデンシャル）。それ以外のトリガー — timer・window 満了・ユーザ/外部 push・poll・非準拠な外部クレデンシャルの到着 — は **FirstDrop** を発行する。

- 賢さより判定可能性: 非イベントトリガーの実行がたまたま pending 1 件だけを処理しても FirstDrop（batch-of-1 規則）。
- fan-out は許容: 線形性が制約するのは各クレデンシャルの親が単数であることのみで、子は複数あってよい — チェーンは前方向に分岐し得る。
- FirstDrop はオリジンコミットメントを運んで**よい**（audit-reachable conformance class — [originsource/README.md](originsource/README.md) 参照）: 消費した source 集合への監査属性であり、親リンクではない。トリガー意味論と線形性には影響しない。

| 用語 | 操作 | トリガー | chain |
|---|---|---|---|
| **Enrichment** | トリガーとなったイベントに外部データを side-fetch して join | 前イベント | 保持（`provin:enrich`） |
| **Boundary translation** | 外部 ecosystem クレデンシャル（SCITT 等）を dplaax クレデンシャルに再署名 | 非準拠クレデンシャルの到着 | FirstDrop |
| **Aggregation** | プールされた N 入力を 1 出力にたたみ込む | timer / window | FirstDrop（`aggregate`） |

## ProcessPattern（deploy 層の分類）

wire コンポーネント型と直交する。deployment config と docs にのみ現れ、import path には現れない:

| ProcessPattern | Wire type | 役割 |
|---|---|---|
| ExternalIn | Origin Source | 外部 → pipeline（chain 開始） |
| ChainedPipeline | FilterConvert | pipeline → pipeline（chain 継続; enrichment を含む step 群） |
| ExternalOut | External Sink | pipeline → 外部（chain 終端） |

## レイアウト

```
contract/        Pipeline Contract — 公開コントラクト。外部アダプタリポジトリはこれを実装する。
                 Custom コンポーネントはここで表現される（専用ディレクトリなし）。
filterconvert/   FilterConvert ランタイム（filter / converter ステップ、VC 署名）
originsource/    Origin Source メカニクス（externalsource / aggregate）
externalsink/    External Sink（コンソール参照実装）
provenance/      共有メカニクス：VC 署名・検証プロバイダ
observer/        共有メカニクス：プロセスイベントオブザーバ（ログ、VC ストア）
transport/       共有メカニクス：pub-sub 抽象（NATS 実装；Hub スワップポイント）
```

コンポーネント型ディレクトリは**プロトコル上の位置づけ**を表す。共有メカニクスパッケージ（`provenance/`、`observer/`、`transport/`）はコンポーネントのセマンティクスを持たない。特定のバイナリが Origin Source なのかチェーン保持型フォワーダーなのかは、ディレクトリではなく署名パス（FirstDrop か `previousCredential` の引き継ぎか）によって決まる。

## 参照実装と拡張アダプタ

本リポジトリは参照実装（`apipush`、`console`）のみを提供する。ベンダー・エコシステムアダプタ（EDC、Kafka、SNS など）は、`contract/` を実装した**別リポジトリ**に置く。このコントラクトの安定性を保つことが、本レイヤーの主要な API 義務である。
