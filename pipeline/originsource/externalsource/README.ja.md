# externalsource — Origin Source メカニクス: 外部インジェスト
> 日本語版 — English: [README.md](README.md)

パイプラインネットワーク外からのインジェスト。トリガーが Pipeline-conformant な前イベントになることはない（HTTP push・ファイル到着・poll・非準拠な外部クレデンシャルの到着）ため、トリガー規則により発行されるクレデンシャルは FirstDrop — 純粋なチェーンオリジンである。

**Boundary translation** はこのメカニクスの特殊形: 外部 ecosystem クレデンシャル（SCITT・GAIA-X 等）が到着し、アダプタ自身のロジックで検証された後、dplaax の FirstDrop として再署名される。外部クレデンシャルへのリンクはデータペイロードの関心事であり、クレデンシャルフィールドにはしない。

## 参照実装：apipush/

HTTP プッシュエンドポイント（`POST /push`、JSON のみ、ボディサイズ上限あり）がコンポーネントの入力キューにパブリッシュし、`GET /health` も提供する。署名パスに関する注記：PoC 参照実装は検証戦略 `none` で設定された下流 FilterConvert チェーンヘッドに向けて生のペイロードをパブリッシュする。自己完結型の署名バリアント（FirstDrop 自身を発行する）も同様に `pipeline/contract` に準拠する。

その他の外部ソースメカニクス（ファイルリーダー、スケジューラ・ポーラー、アーカイブリプレイ）も同じ形状に従い、ここまたは拡張リポジトリに置かれる。
