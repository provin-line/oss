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

## レイアウト

```
contract/        Pipeline Contract — 公開コントラクト。外部アダプタリポジトリはこれを実装する。
                 Custom コンポーネントはここで表現される（専用ディレクトリなし）。
filterconvert/   FilterConvert ランタイム（filter / converter ステップ、VC 署名）
originsource/    Origin Source バリアント（externalsource / enrichment / aggregate）
externalsink/    External Sink（コンソール参照実装）
provenance/      共有メカニクス：VC 署名・検証プロバイダ
observer/        共有メカニクス：プロセスイベントオブザーバ（ログ、VC ストア）
transport/       共有メカニクス：pub-sub 抽象（NATS 実装；Hub スワップポイント）
```

コンポーネント型ディレクトリは**プロトコル上の位置づけ**を表す。共有メカニクスパッケージ（`provenance/`、`observer/`、`transport/`）はコンポーネントのセマンティクスを持たない。特定のバイナリが Origin Source なのかチェーン保持型フォワーダーなのかは、ディレクトリではなく署名パス（FirstDrop か `previousCredential` の引き継ぎか）によって決まる。

## 参照実装と拡張アダプタ

本リポジトリは参照実装（`apipush`、`console`）のみを提供する。ベンダー・エコシステムアダプタ（EDC、Kafka、SNS など）は、`contract/` を実装した**別リポジトリ**に置く。このコントラクトの安定性を保つことが、本レイヤーの主要な API 義務である。
