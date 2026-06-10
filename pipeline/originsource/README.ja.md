# originsource — FirstDrop 発行コンポーネント
> 日本語版 — English: [README.md](README.md)

Origin Source コンポーネント型。その**唯一の定義的性質**は、新たな FirstDrop VC を発行すること（`previousCredential` が空 — チェーンを切断する）。内部メカニクス — 入力カーディナリティ、プール・キャッシュ状態、外部ルックアップ、集約ロジック — はプロトコル非可視であり、実装が自由に選択できる。

## 線形チェーン不変 — 上流参照フィールドは持たない

チェーンは厳密に線形である: Origin Source の FirstDrop は上流参照のクレデンシャルフィールドを**一切持たない**（`derived_from` / `source_root` は設計から撤去された — Paper 01 §4.8 がクレデンシャルスキーマ層での定義を禁止）。集約は上流データとの同一性を断ち切る。チェーンが証明するのは「集約地点以降にこのデータへ何が起きたか」である。どの入力を使ったかの記録が必要な場合、それは集約器のビジネスロジックとしてデータペイロードに置く — クレデンシャルには置かない。

## トリガー規則

境界がチェーンを保持するか開始するかは**トリガー規則**で決まる（provin wire profile の規範 — [pipeline/README.md](../README.md) 参照）: Origin Source メカニクスとは、実行が「Pipeline-conformant な前イベント 1 件」によって起動され**ない**境界のことである。

## メカニクス（参照実装の命名）

| メカニクス | トリガー | 内部形状 | 本リポジトリでのステータス |
|---|---|---|---|
| `externalsource/` | 外部 push / ファイル / poll / 非準拠クレデンシャルの到着（boundary translation） | ステートレスなインジェスト | `apipush/` 参照実装あり |
| `aggregate/` | プールされた Pipeline-conformant 入力に対する timer / window | プール + ウィンドウ（ステートフル） | 規約のみ |

Enrichment は Origin Source メカニクス**ではない**: チェーンを保持する FilterConvert の step pattern である（[../filterconvert/README.md](../filterconvert/README.md) 参照）。

メカニクスは規約であり、型コントラクトの区別ではない — プロトコルレベルでは Origin Source 型は厳密に1つ。
