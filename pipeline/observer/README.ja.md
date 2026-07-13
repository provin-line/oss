# observer — プロセスイベントオブザーバ
> 日本語版 — English: [README.md](README.md)

処理済みイベントごとに通知される `ProcessObserver` 実装（`OnProcessComplete(ctx, ProcessEvent)`）。

## 状態

**拡張点は稼働済み**: `contract.ProcessObserver` が定義され、全ランタイム（`ingest`・`aggregate`・`chained`・`sink`）が `Observers` config フィールドを持ち、すべての outcome の後に fire-and-forget で呼び出される。`logobserver/` は**参照実装として提供**、`vcobserver/` は予定:

- `logobserver/` — 参照 `ProcessObserver`: 各イベントのフィールド（status・hash・role 別 VC ref・confidence・filtered step）を 1 本の構造化 `slog` レコードとして emit する。最小・依存なしで、実アダプタを書く際に**複製する雛形**。opt-in（default ではどのランタイムにも配線されない）。
- `vcobserver/` —（予定）ストア連携オブザーバ。監査上重要な保存経路は現状これ**なし**で成立している: 発行済み credential はデータプレーン配線の VC-store クライアント（`cmd/standalone`、`vc-store-endpoint`）がネットワーク VC ストアへ公開し、検証済みイングレス credential は `contract.IngressVCStore` 経由で永続化される — 下記参照。

## 規約

- オブザーバは**ファイアアンドフォーゲット**：失敗はログ記録されるが、処理パスには伝播しない — 観測がパイプラインの結果に影響してはならない。
- イングレス VC ストア義務（検証を行うプロセスは検証したものを保存しなければならない）は、**同期的なライフサイクル義務**である — `contract.IngressVCStore` を検証と変換の間に呼び出し、保存失敗は event を失敗させる。これはオブザーバでは**ない**: fire-and-forget なのは観測イベント自体だけである。
