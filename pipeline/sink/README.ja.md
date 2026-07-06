# sink — Sink Process: チェーン終端
> 日本語版 — English: [README.md](README.md)

Sink Process 型：パイプライン出力を消費・検証し、外部世界に書き出す。VC チェーンはネットワーク内で終端し、シンクはネットワーク内に何も出力しない。

## 規約

- シンクは消費するものを検証する（通常はフルチェーン戦略 — シンクはネットワーク内の最後のオブザーバーである）。外部に出力する際は、検証の verdict をペイロードとともに表示する。
- シンクはパイプラインサブジェクトに再パブリッシュしない。そうすることは、そのプロセスを事実上 Chained Process または Source Process にしてしまう。

## Sink kind（deploy 層の属性、`contract.SinkKind`）

| Kind | invalid emit | reject | 相互 allow-list | receipt |
|---|---|---|---|---|
| observation-only | MAY | 不要 | 緩和 | 不要 |
| production | 禁止 | MUST | MUST 強制 | MAY |
| archival | 禁止 | MUST + 監査ログ | MUST 強制 | MUST |

Sink kind は deploy されたプロセスの config 駆動の属性であり、独立したプロセス型ではない。再配送イベントへの冪等性チェックは sink 側の義務（production / archival）。

## 参照実装：console/（observation-only）

出力サブジェクトをサブスクライブし、受信した各 VC を検証（署名 / DID 解決 / スキーマの各軸）して、イベントごとに1つの NDJSON レコードを stdout に書き出す — 開発・検査ツールとして機能する。ベンダーシンク（EDC、ウェアハウスなど）は `pipeline/contract` を実装した拡張リポジトリに置く。

## 参照実装：file/（永続 NDJSON ストリーム）

`console/` と同一の行形式（構造上同一 — append モードのファイルハンドル上に console writer を埋め込む）を、プロセス stdout をスクレイプせずに tail できるファイルへ書き出す。sink ループごとに `sink.output { type = "file", path = ... }` で選択する。同一 path を共有するループは writer を共有するため、行が交錯することはない。これは配送ストリームであり evidence ストアではない — evidence の永続性は VC / verdict ストアが担う。
