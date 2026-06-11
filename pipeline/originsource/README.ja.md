# originsource — FirstDrop 発行コンポーネント
> 日本語版 — English: [README.md](README.md)

Origin Source コンポーネント型。その**唯一の定義的性質**は、新たな FirstDrop VC を発行すること（`previousCredential` が空 — チェーンを切断する）。内部メカニクス — 入力カーディナリティ、プール・キャッシュ状態、外部ルックアップ、集約ロジック — はプロトコル非可視であり、実装が自由に選択できる。

## 線形チェーン不変 — と任意のソースコミットメント

チェーンは厳密に線形である: Origin Source の FirstDrop は**上流リンクを一切持たない**。集約は上流データとの同一性を断ち切る。チェーンが証明するのは「集約地点以降にこのデータへ何が起きたか」である。入力マニフェストが必要な場合、それは集約器のビジネスロジックとしてデータペイロードに置く。Paper 01 §4.8 の排除は**チェーントポロジー**（DAG 化・親リンクの禁止）と**ベースクレデンシャルスキーマ**（上流参照フィールドなし）についての主張であり — どちらもそのまま維持される。

FirstDrop が追加で運んで**よい**のが**ソースコミットメント**（`derived_from` / `source_root` / `source_root_canonical` — `vc.SourceCommitment` 参照）: 発行時点で claim した source 集合に発行者を拘束する、dplaax JSON-LD context で宣言される wire-profile 監査属性である。コミットメントは FirstDrop 専用ではない — `previousCredential` と直交し、chain-preserving 境界はトリガーの先行イベントを含む全消費分に commit する（全消費分セマンティクス）。本節は集約起点での用法を述べる。これは content commitment であって親リンクではない — 検証器はイベント毎経路でこれを走査せず、監査者が claim された source を非同期に解決してオンデマンドで root を再計算する。

これを emit するのが **audit-reachable conformance class**: deployment ごとの config 駆動であり、wire profile 自体は要求しない。deployment profile（例: バッテリーパスポートのような規制ドメイン）はこの class を必須化できる; class 外では plain な FirstDrop が完全に conformant である。コミットメントが証明するのは「claim が発行後に改変されていないこと」であり、claim の完全性ではない。申告漏れの検出は監査層の突合作業 — claim された commitment と取引相手のイングレス VC ストアの照合（署名済み記録上の mass-balance）— である。

## トリガー規則

境界がチェーンを保持するか開始するかは**トリガー規則**で決まる（provin wire profile の規範 — [pipeline/README.md](../README.md) 参照）: Origin Source メカニクスとは、実行が「Pipeline-conformant な前イベント 1 件」によって起動され**ない**境界のことである。

## メカニクス（参照実装の命名）

| メカニクス | トリガー | 内部形状 | 本リポジトリでのステータス |
|---|---|---|---|
| `externalsource/` | 外部 push / ファイル / poll / 非準拠クレデンシャルの到着（boundary translation） | ステートレスなインジェスト | `apipush/` 参照実装あり |
| `aggregate/` | プールされた Pipeline-conformant 入力に対する timer / window | プール + ウィンドウ（ステートフル） | 規約のみ |

Enrichment は Origin Source メカニクス**ではない**: チェーンを保持する FilterConvert の step pattern である（[../filterconvert/README.md](../filterconvert/README.md) 参照）。

メカニクスは規約であり、型コントラクトの区別ではない — プロトコルレベルでは Origin Source 型は厳密に1つ。
