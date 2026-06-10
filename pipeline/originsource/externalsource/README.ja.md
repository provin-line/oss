# externalsource — Origin Source バリアント、N = 0
> 日本語版 — English: [README.md](README.md)

パイプラインネットワーク外からのインジェスト。パイプライン準拠入力がないため、`derived_from` / `source_root` コミットメントを持たない — 発行される FirstDrop は純粋なチェーンオリジンである。

## 参照実装：apipush/

HTTP プッシュエンドポイント（`POST /push`、JSON のみ、ボディサイズ上限あり）がコンポーネントの入力キューにパブリッシュし、`GET /health` も提供する。署名パスに関する注記：PoC 参照実装は検証戦略 `none` で設定された下流 FilterConvert チェーンヘッドに向けて生のペイロードをパブリッシュする。自己完結型の署名バリアント（FirstDrop 自身を発行する）も同様に `pipeline/contract` に準拠する。

その他の外部ソースメカニクス（ファイルリーダー、スケジューラ・ポーラー、アーカイブリプレイ）も同じ形状に従い、ここまたは拡張リポジトリに置かれる。
