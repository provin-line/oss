# chained — Chained Process: ステートレスな1:1変換
> 日本語版 — English: [README.md](README.md)

Chained Process 型。**ステートレス性は定義的性質**であり、データベース、プール、キャッシュ、クロスイベント状態を持たない。ステートフルな振る舞いは Source Process に属する。

## 処理ライフサイクル（1イベント）

```
ingress VC verification (strategy: adjacent — the only ingress strategy;
                         full-chain audit is the async audit runner's job)
  → ingress VC store (synchronous; a verified input that cannot be stored
                      fails the event — audit reachability)
  → payload extraction (by-reference ingress dereferences a nil payload
                        via PayloadResolver first)
  → payload↔credential binding (sha256(payload) == predecessor's outputHash;
                                mismatch or missing outputHash fails the event)
  → optional input-schema check
  → ordered steps: filter (JSONata; falsy ⇒ "filtered", drop)
                   converter (JSONata; whole-doc or per-field steps mode)
  → optional output validation against the pinned schema version
  → strict decode (duplicate-key reject, precision preserve)
  → inputHash / outputHash computation (sha256)
  → VC signing (chain-preserving: previousCredential = hash of input VC)
  → observer notification (fire-and-forget) → publish
```

不変条件：隣接するチェーンリンク間で `outputHash[n] == inputHash[n+1]` — 下流ステージはペイロードを再読みすることなくデータフローの連続性を証明できる。

## ステップカタログ（provin step catalog、`contract.StepKind`）

| Step | 役割 | PoC ステータス |
|---|---|---|
| ConvertFlow | ステートレスなペイロード変換 | 実装あり（`converter/`） |
| FilterFlow | ステートレスな条件付き pass / drop | 実装あり（`filter/`） |
| VerifierFlow | envelope unmarshal + 署名検証 + reject | 実装あり（runtime ingress） |
| BatchFlow | fresh output を生成する batch API call、ステートレス | 型のみ |
| SinkedSourceFlow | イベントごとの外部データ fetch — **enrichment** ステップ | 型のみ |

**Enrichment**（トリガーとなったイベントへの外部データの side-fetch join）は Chained Process の step pattern であり、Source Process メカニクスではない: 実行は前イベントによってトリガーされるため、チェーンは保持される（`transformationClaim: "provin:enrich"`）。すべてのステップはイベント単位でステートレス。クロスイベント状態を持てば、そのプロセスは Source Process になる。

## サブパッケージ

- `filter/` — `Filter` インターフェース（`Apply(ctx, data) (*Result, error)`）；`jsonata/` 実装（起動時に式をプリコンパイル；すべてが truthy であればパス）
- `converter/` — `Converter` インターフェース + サブセット出力バリデータ；`jsonata/` 実装（ドキュメント全体モードとシーケンシャルなフィールド別ステップモード）
- `cmd/` — スタンドアロンなランタイムバイナリ用に予約。**まだ未実装**。PoC では chained ループは `cmd/standalone`（データプレーン配線）内で動く

## エラーセマンティクス（PoC）

フィルタリングされたイベントはサイレントにドロップ（ログ記録）；エラーが発生したイベントはラウドにドロップ（ログ記録）。リトライもデッドレターキューもなし — デッドレタリングは後でプラグインされるセームとして、トランスポートループに位置する。

## ランタイム（package chained）

**Config フィールド** — `Strategy`、`IngressConformant`、`UpstreamEndpoint`、`Codec`、
`Verifier`（直前 credential の adjacent 検証）、`Store`、`Signer`、`Filters`、
`Converter`（nil = パススルー）、`InputValidator`/`InputSchemaRef`、
`OutputValidator`/`OutputSchemaRef`、`PayloadDelivery`/`PayloadResolver`、
`Observers`、`Logger`、`Now`。

**Strategy 制約** — `VerificationNone` および `VerificationUnknown` は構築時に拒否される。
Chained Process はチェーン保持型クレデンシャルを発行するため、イベントごとに検証済みの predecessor
が必要。準拠 ingress のないランは trigger ルールにより FirstDrop となり、Source Process
ランタイムに属する。`IngressConformant` も `true` でなければならない（宣言マトリクス要件）。

**フェイルクローズ検証ポリシー（2026-06-12 確定）** — `ConfidenceVerified` のみが処理を続行する。
`ConfidenceFailed` および `ConfidenceIndeterminate` はどちらも `StatusErrored` にマップされる。
indeterminate を通過させる observation-class の寛容性は sink の `SinkKind` 属性であり、生産プロセスには決して属さない。
runtime はさらに変換前に payload↔credential binding を強制する — verifier は credential しか持たず、
両方の artifact を持つ唯一の当事者は runtime である。これにより自身が発行する link の chain 連続性が
by construction で保証される。

**by-reference ingress** — `PayloadDelivery` は ingress の合意済み配信モードを宣言する。
inline（ゼロ値）は envelope 内の payload バイト列を期待し、`DeliveryByReference` は `nil`
payload を `PayloadResolver` でコンテンツアドレスから解決する（resolver 欠落時は `New` が
fail-closed）。宣言モードと payload の有無が矛盾する場合は決定可能なプロトコル違反として
`StatusErrored` になる。

**Result / Go error の分割** — ドメイン障害（検証・ストア・nil ペイロード・スキーマ・フィルタ・
コンバータ・strict-decode・署名）は `Error` 文字列を持つ `StatusErrored` の `*Result` として返す。
`Process` は `(result, nil)` を返す。Go error の戻り値はコンテキストキャンセル（`ctx.Err()`）と
内部不変条件違反のためにのみ使用する。
