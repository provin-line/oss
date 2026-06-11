# transport — Pub-Sub 抽象
> 日本語版 — English: [README.md](README.md)

Pipeline プロセス間のメッセージング境界：`Publisher` / `Subscriber` インターフェースと、プロセスのイベントプロセッサを駆動する消費・処理・パブリッシュのランタイムループ。

## 規約

- ここは pub-sub バックエンドの**Hub スワップポイント**である：`nats/`（JetStream）が OSS デフォルト；SQS/SNS その他はプロセスロジックに触れることなくここで置き換える。
- `envelopecodec/` はパイプライン envelope の wire codec（`contract.EnvelopeCodec` の参照実装、`dplaax.pipeline.v1` 上）。stateless かつ購読非依存：wire 上の payload 不在は nil（by-reference）に写像し、不在が正当かどうかは購読の合意配送モードを知る層が判定する — codec は決して判定しない。空 inline payload（marshal 側）と sequence number ゼロ（両方向）は fail-closed に拒否する。codec 外モード検査の覆す条件：runtime loop の実装で「配送モードを知る単一の層が存在しない」と判明した場合は mode-aware なラッパーを純追加する — 検査をこの codec に押し込むことは決してしない。
- サブジェクト命名、クレデンシャル、接続ライフサイクル（シャットダウン時のドレイン、サブスクライブ後のフラッシュ）はここで管理 — プロセスはブローカークライアントを直接インポートしない。
- ランタイムループは意図的に最小限：メッセージごとの同期処理、「passed」でパブリッシュ（生産プロセスのみ — 終端プロセスは外部に書き出し、何もパブリッシュしない）、「filtered」/「error」でログ付きドロップ。リトライ / デッドレターポリシーはプロセス内部ではなく、このセームでプラグインされる。
- 組織間の配線（アカウント間のインポート / エクスポート）はこのパッケージの責務**ではない** — それはネットワーク chainmanager の `InfraOperator` に属する。
- **Payload 配送モード**: 自組織内では、プロセスは常に full（inline）envelope を生成する。購読ごとの合意モード（`inline` / `by-reference` — `Envelope` の契約と chainmanager の `Subscription` record を参照）は組織間エクスポート境界で適用され、その実現方法は各バックエンド固有（モード別 subject / topic、または strip 変換）。by-reference 化は payload を剥がすだけで一方向に安い — 逆方向は fetch なしには不可能。
- **Emission ログ**: publisher 側は publish した各イベント（credential hash + sequence number）を `tlog` のログに記録する — 監査突合モデルが依存する「配送実績」の記録。記録される同一性は配送形態に依存しない: 同じイベントは inline で配ろうと by-reference で配ろうと同じ記録になる。監査期間にわたる保持は deployment 義務。
