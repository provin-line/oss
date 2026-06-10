# aggregate — Origin Source メカニクス: プール + ウィンドウ
> 日本語版 — English: [README.md](README.md)

1つ以上のパイプライン準拠入力（スキーマが異なる場合も可）に対してプール + ウィンドウ / 集約ロジックを実行し、新しいスキーマを持つ新たな FirstDrop を発行する。

## 規約

- **ステートフル**なパイプラインワークロード（プール、ウィンドウ、ジョイン）が属する場所はここである — FilterConvert のステートレス性は定義的性質であるため、集約はそちらに移行できない。
- 実行は timer / window 満了でトリガーされる — 単一の前イベントによってではない — ため、出力は `transformationType: "aggregate"` の FirstDrop になる（トリガー規則）。たまたま pending 1 件だけをたたみ込んだ実行も FirstDrop（batch-of-1 規則）。
- どの入力を使ったかの記録は任意で、集約器のビジネスロジックとして出力ペイロードに置く。outputHash = sha256(output) が発行者署名で束縛されるため、改竄防止は追加コストなしで成立する。クレデンシャルフィールドには決してしない（Paper 01 §4.8）。
- 消費する各入力に対して、イングレス検証 + イングレス VC ストア義務が適用される。
- プール・キャッシュ状態は内部メカニクスであり、プロトコル非可視で実装の選択に委ねられる（インメモリ、組み込み KV など）— ただしコントラクト面に漏出してはならない。

## 監査時の責任追跡（accountability）

チェーンの切断は責任の空白を作らない — 切断者に責任を集中させ、事後監査は上流への責任帰属も可能なまま保つ:

1. **責任のデフォルト規則**: FirstDrop は集約器の Process DID で署名され、controller 連鎖で Owner DID に到達する。source manifest を記録しない集約器は出力の責任を単独で総取りする。責任を分担する手段が manifest の記録であり、記録された manifest は改竄不能（outputHash + 署名）。
2. **捏造は検出可能**: manifest の各エントリは発行者署名済みの source VC に解決される。捏造 source は解決失敗または署名検証失敗で露見する。
3. **省略は「敵対側の記録」との突合で検出可能**: 集約器が編集も削除もできない記録 — *publisher 側* ChainManager が保持する集約器自身の L2 署名付き RegisterSubscription 記録（否認不能）、publisher の append-only emission stream（sequence number 付き・署名済み）、集約器の ingress VC ストア義務。「B を購読し、B のイベントを受領し、manifest には A だけ」は集約器に固定される監査可能な不整合である。

前提条件: VC resolver と emission 記録が監査期間にわたり保存されていること（deployment 義務 — in-memory の PoC ストアはこれを満たさない）、および federation 外入力の責任は取り込んだ owner で終端すること。

## ステータス

この PoC フェーズではインターフェース + 規約のみ。参照実装はまだ存在しない。
