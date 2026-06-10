# externalsink — チェーン終端コンポーネント
> 日本語版 — English: [README.md](README.md)

External Sink コンポーネント型：パイプライン出力を消費・検証し、外部世界に書き出す。VC チェーンはネットワーク内で終端し、シンクはネットワーク内に何も出力しない。

## 規約

- シンクは消費するものを検証する（通常はフルチェーン戦略 — シンクはネットワーク内の最後のオブザーバーである）。外部に出力する際は、検証の verdict をペイロードとともに表示する。
- シンクはパイプラインサブジェクトに再パブリッシュしない。そうすることは、そのコンポーネントを事実上 FilterConvert または Origin Source にしてしまう。

## Sink kind（deploy 層の属性、`contract.SinkKind`）

| Kind | invalid emit | reject | 相互 allow-list | receipt |
|---|---|---|---|---|
| observation-only | MAY | 不要 | 緩和 | 不要 |
| production | 禁止 | MUST | MUST 強制 | MAY |
| archival | 禁止 | MUST + 監査ログ | MUST 強制 | MUST |

Sink kind は deploy されたコンポーネントの config 駆動の属性であり、独立したコンポーネント型ではない。再配送イベントへの冪等性チェックは sink 側の義務（production / archival）。

## 参照実装：console/（observation-only）

出力サブジェクトをサブスクライブし、受信した各 VC を検証（署名 / DID 解決 / スキーマの各軸）して、イベントごとに1つの NDJSON レコードを stdout に書き出す — 開発・検査ツールとして機能する。ベンダーシンク（EDC、ウェアハウスなど）は `pipeline/contract` を実装した拡張リポジトリに置く。
