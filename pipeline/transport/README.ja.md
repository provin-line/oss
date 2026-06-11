# transport — Pub-Sub 抽象
> 日本語版 — English: [README.md](README.md)

Pipeline コンポーネント間のメッセージング境界：`Publisher` / `Subscriber` インターフェースと、コンポーネントのプロセッサを駆動する消費・処理・パブリッシュのランタイムループ。

## 規約

- ここは pub-sub バックエンドの**Hub スワップポイント**である：`nats/`（JetStream）が OSS デフォルト；SQS/SNS その他はコンポーネントロジックに触れることなくここで置き換える。
- サブジェクト命名、クレデンシャル、接続ライフサイクル（シャットダウン時のドレイン、サブスクライブ後のフラッシュ）はここで管理 — コンポーネントはブローカークライアントを直接インポートしない。
- ランタイムループは意図的に最小限：メッセージごとの同期処理、「passed」でパブリッシュ、「filtered」/「error」でログ付きドロップ。リトライ / デッドレターポリシーはコンポーネント内部ではなく、このセームでプラグインされる。
- 組織間の配線（アカウント間のインポート / エクスポート）はこのパッケージの責務**ではない** — それはネットワーク chainmanager の `InfraOperator` に属する。
- **Payload 配送モード**: 自組織内では、コンポーネントは常に full（inline）envelope を生成する。購読ごとの合意モード（`inline` / `by-reference` — `Envelope` の契約と chainmanager の `Subscription` record を参照）は組織間エクスポート境界で適用され、その実現方法は各バックエンド固有（モード別 subject / topic、または strip 変換）。by-reference 化は payload を剥がすだけで一方向に安い — 逆方向は fetch なしには不可能。
- **Emission ログ**: publisher 側は publish した各イベント（credential hash + sequence number）を `tlog` のログに記録する — 監査突合モデルが依存する「配送実績」の記録。記録される同一性は配送形態に依存しない: 同じイベントは inline で配ろうと by-reference で配ろうと同じ記録になる。監査期間にわたる保持は deployment 義務。
