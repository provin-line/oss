# transport — Pub-Sub 抽象

> 日本語版 — English: [README.md](README.md)

Pipeline プロセス間のメッセージング境界：`Publisher` / `Subscriber` インターフェースと、プロセスのイベントプロセッサを駆動する消費・処理・パブリッシュのランタイムループ。

## 規約

- ここは pub-sub バックエンドの**Hub スワップポイント**である：`nats/`（JetStream）が OSS デフォルト；SQS/SNS その他はプロセスロジックに触れることなくここで置き換える。
- `envelopecodec/` はパイプライン envelope の wire codec（`contract.EnvelopeCodec` の参照実装、`dplaax.pipeline.v1` 上）。stateless かつ購読非依存：wire 上の payload 不在は nil（by-reference）に写像し、不在が正当かどうかは購読の合意配送モードを知る層が判定する — codec は決して判定しない。空 inline payload（marshal 側）と sequence number ゼロ（両方向）は fail-closed に拒否する。codec 外モード検査の覆す条件：runtime loop の実装で「配送モードを知る単一の層が存在しない」と判明した場合は mode-aware なラッパーを純追加する — 検査をこの codec に押し込むことは決してしない。
- サブジェクト命名、クレデンシャル、接続ライフサイクル（シャットダウン時のドレイン、サブスクライブ後のフラッシュ）はここで管理 — プロセスはブローカークライアントを直接インポートしない。
- ランタイムループは意図的に最小限：メッセージごとの同期処理、「passed」でパブリッシュ（生産プロセスのみ — 終端プロセスは外部に書き出し、何もパブリッシュしない）、「filtered」/「error」でログ付きドロップ。リトライ / デッドレターポリシーはプロセス内部ではなく、このセームでプラグインされる。
  `Loop`（`loop.go`）は `contract.Process` を実装し、1 つの購読を駆動する：
  - **成功時のシーケンス採番**: publisher が割り当てるシーケンス番号は `Publish` 呼び出しが成功した場合にのみ進める。Publish が失敗した場合は次回の試行で同じ番号を再利用する。subscriber 側から見てギャップが生じることは改ざんの証拠 — publisher が自身の失敗でギャップを作ることは許されない。ハンドラは購読ごとに直列（Subscriber 契約）なので、失敗時の番号再利用はミューテックスなしに race-free である。
  - **パブリッシュ後の Emission 追記**: emission ログのエントリ（credential hash + シーケンス番号）は `Publish` 成功後に `tlog` へ追記する。`Append` はデタッチされたコンテキスト（`context.WithoutCancel`）を受け取るため、グレースフルシャットダウン時に ctx がキャンセルされても、すでに配送済みのイベントの記録が中断されることはない。`Process` はキャンセル可能な ctx を保持し続ける — スタックしたプロセッサは割り込み可能でなければならない。`Append` が失敗した場合でもイベントはすでに配送済みであり、ギャップは publisher 自身の監査防御上の損失となる。シーケンスカウンタは引き続き進める。`Publish` と `Append` の間でクラッシュすると未記録の配送ウィンドウが生じる（PoC ポスチャ — 永続化 WAL は将来対応）。
  - **sequenceNo エンコーディング**: emission レコード JSON のシーケンス番号は文字列（`"1"`、`1` でない）でエンコードする — 整数精度が 2^53 に限定される IEEE-754 JSON コンシューマでも丸め誤差が生じない。
  - **インメモリシーケンスリセット**: カウンタはプロセス再起動時に 1 にリセットされ、subscriber 視点の再起動をまたいだ単調性が保証されない。受け入れ済みの PoC ポスチャ（wireauth のインメモリ nonce ストアと同種）；永続化シーケンス状態は将来対応。
  - **シンクループ**: `ChainTerminating` ループは何もパブリッシュしない。シンクに `Publisher`、`Codec`、または `Emission` を配線するのは誤設定であり `ErrSinkWithPublisher` を返す。
- 組織間の配線（アカウント間のインポート / エクスポート）はこのパッケージの責務**ではない** — それはネットワーク chainmanager の `InfraOperator` に属する。
- **Payload 配送モード**: 自組織内では、プロセスは常に full（inline）envelope を生成する。購読ごとの合意モード（`inline` / `by-reference` — `Envelope` の契約と chainmanager の `Subscription` record を参照）は組織間エクスポート境界で適用される。account の export/import はルーティング権限であり message の変換ではないため、seam は飛行中の envelope を書き換えられない — そこで serving する生産ループは代わりに **dual-emit** する: `Emitter` のオプション capability `WithStrippedPublisher` は、primary publish と**同一のシーケンス番号**で、各イベントの stripped 形（`Payload: nil`）を第二の `Publisher` へ追加 publish する。この第二 Publisher は composition root で、そのループの by-reference 購読者向けに chainmanager が export する mode-scoped subject（NATS では `"byref."` 接頭辞付き subject）へ bind される。どの subscriber account がどちらの形を見られるかは、もっぱら export/import の権限次第であり、ランタイムの分岐ではない。stripped publish の失敗は `Emit` を失敗させない — primary は既に配送済みであり、ここで失敗させると seq 再利用のリトライが primary 配送を**重複**させてしまう（stripped 形自身の at-most-once 損失より悪い — 既存の emission-log シーケンスギャップ検出が POSSIBLE LOSS として既にカバーしている）。失敗は代わりに `Emitter.StrippedPublishFailures()`（と `LastStrippedPublishFailure()`）を増加させる — 将来の health/metrics サーフェスの配線点である。by-reference 化は payload を剥がすだけで一方向に安い — 逆方向は fetch なしには不可能。
- **Emission ログ**: publisher 側は publish した各イベント（credential hash + sequence number）を `tlog` のログに記録する — 監査突合モデルが依存する「配送実績」の記録。記録される同一性は配送形態に依存しない: 同じイベントは inline で配ろうと by-reference で配ろうと同じ記録になる。監査期間にわたる保持は deployment 義務。
