# pipeline/contract — The Pipeline Contract
> 日本語版 — English: [README.md](README.md)

すべての Pipeline プロセスが少なくとも1つのI/O側で準拠すべき公開コントラクト。**外部アダプタリポジトリがインポートするパッケージ**であり、リポジトリ内で最も厳格な安定性義務を持つ。

## コントラクトがカバーする範囲

1. **I/O形状** — プロセスがパイプライントランスポートから消費し、またはそこへ生産する方法: `Envelope`（credential + 任意の inline payload + sequence number）とサブジェクト規約。**規範的意味論は hash ベース**であり、payload を inline で運ぶか参照で運ぶかは購読ごとの transport 選択 — 検証は配送形態に依存しない。
2. **VCチェーンの振る舞い** — 出力側ごとに必ず1つ：
   - *チェーン保持*：出力 VC が `previousCredential` = 入力 VC のハッシュを持つ（Chained Process。audit-reachable な deployment は加えて、トリガーの先行イベントを含む全消費分へのソースコミットメントを付与する）
   - *FirstDrop 発行*：出力 VC は `previousCredential` を持たない — 新しいチェーン起点（Source Process: 外部インジェストまたは集約。入力マニフェストはデータペイロードの関心事。audit-reachable な deployment は加えてソースコミットメントを付与する — 監査属性であり、親リンクではない）
   - *終端*：消費・検証を行い、ネットワーク内に何も生産しない（Sink Process）
3. **イングレス時の検証義務** — プロセスが入力を信頼する前に実行すべき検証戦略（none / adjacent / full）、および監査到達性のために検証済みイングレス VC を保存する義務。

## メソッドセット（確定）

- **`Process` が唯一の必須コントラクト**: `Run` と宣言メソッド群（`ChainBehavior()` / `VerificationStrategy()`）。1 つの `Process` 値は exactly 1 つのパイプライン出力側（または終端消費者）を表す。複数出力側を持つ Custom Process は出力側ごとに `Process` を構成して compose する。
- **`EventProcessor` は optional** — event-triggered な処理のコントラクトであり、transport の runtime loop が駆動する単位（1 入力イベント → 1 `Result`）。トリガーを自前で持つ mechanics（timer / window 集約）は `Process` を直接実装する。first-stage の push インジェストは event-triggered（push がイベント）。
- **宣言はインスタンスレベル**: `ChainBehavior()` はプロセス型に内在する。`VerificationStrategy()` は構築時に確定し（同一コードが chain-head では `none`、中間段では `adjacent` で走り得る）、宣言対象は Pipeline-conformant な ingress 側のみ — 全面に一様に適用される floor 義務。非準拠入力は定義上検証不能。
- **`Result` 不変条件**（生産プロセス、`StatusPassed`）: `sha256(Payload) == outputHash`、かつ `Payload` は空であってはならない（profile 規範 — proto3 では空と不在が wire 上同一であり、空の禁止により inline 購読での payload 不在が決定可能な違反になる）。
- **`Confidence` はすべての `Result` でポインタ**: nil = 検証未実施 — 不在はコントラクト層の概念であり、confidence 格子の状態には決してならない。終端プロセス（sink）では verdict そのものを運ぶ。

## 規約

- ここに定義するインターフェースはトランスポート非依存かつ VC 実装非依存である。依存するのは `vc` の型と `pipeline/transport` の抽象のみ — NATS にも `gen/` にも依存しない。
- コントラクト義務を満たせないプロセスは、ランタイムで暗黙的に劣化するのではなく、起動時に失敗しなければならない。検証宣言の起動時強制は二分される: `strategy ≠ none ⇒ IngressVCStore 構成済み` は宣言単体で完結する検査、`none` 宣言の正当性は deploy wiring metadata との突合で検査する。
- バージョニング：このパッケージへの破壊的変更は、まずメジャーなプロトコル議論を必要とする — 外部リポジトリがこれをビルド対象としているため。
