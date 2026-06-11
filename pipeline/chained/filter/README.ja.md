# filter — FilterFlow ステップ契約

> 日本語版 — English: [README.md](README.md)

FilterFlow ステップを定義する：単一イベントペイロードに対するステートレスな条件付き pass/drop。**ステートレス性は定義的性質** — クロスイベント状態、キャッシュ、プールを持たない。

## インターフェース

```go
type Filter interface {
    Apply(ctx context.Context, data []byte) (*Result, error)
}

type Result struct {
    Pass bool
}
```

`Apply` は唯一の呼び出し口。並行呼び出しに対して安全でなければならない。

## エラー vs フィルタリングの区別

この2つの結果は意図的に分離されている：

| 結果 | 意味 | プロセッサが対応するステータス |
| --- | --- | --- |
| `err != nil` | ステップ失敗（式評価エラー、無効な JSON） | `StatusErrored` — ラウドにドロップ |
| `Pass=false, err=nil` | 偽値の判定 — イベントを意図的にドロップ | `StatusFiltered` — サイレントにドロップ |

エラーはフィルタ結果ではない。フィルタ結果はエラーではない。

## サブパッケージ

### `jsonata/`

`Filter` の JSONata 実装。主な特性：

- **起動時プリコンパイル**：すべての式は `New` でコンパイルされる。コンパイルエラーや空リストは構築時に失敗する。フィルタは実行時に劣化しない。
- **全 truthy セマンティクス**：`Pass=true` となるにはすべての式が truthy な結果を返す必要がある。最初の falsy な結果で評価は短絡する。
- **undefined は falsy**：JSONata のノーマッチ（フィールド未存在、空パス）は `Pass=false`、`err=nil` を返す — フィルタの判定であり、ステップ失敗ではない。
- **Truthiness ルール** — `jlib.Boolean`（jsonata-go 自身の `$boolean()` 実装）に委譲することで正確に実装される：
  - `false` / `null` / undefined → falsy
  - `0` → falsy；それ以外の数値 → truthy（`$count(...)` や `$length(...)` 等の組み込み関数が返す `int` 型も含む）
  - `""` → falsy；非空文字列 → truthy
  - 空配列 → falsy；空オブジェクト → falsy；それ以外 → truthy
- **厳格な入力デコード**：`Apply` は `canon.StrictDecoder` で入力をデコードする。重複キー（例: `{"value":0,"value":20}`）や末尾データは式評価に到達する前にエラーとして拒否される。
- **数値モデル**：`StrictDecoder` は数値を `json.Number` として保持する。JSONata 評価前に正規化される — `int64` に収まる整数値は `int64`、それ以外は `float64` に変換。JSONata 式の内部では、演算と比較は `float64` で行われる。整数の同一性は Go の値ツリー内では `int64` の範囲まで保持されるが、2^53 超の整数は JSONata の演算・比較に入ると精度を失う。固定された動作は `TestApplyIntegerPrecision` を参照。
- **並行安全性**：`jsonata-go` の `Expr.Eval` は呼び出しごとに新しい環境を生成し、コンパイル済み状態を変更なく読み取る。同一の `*Filter` に対する並行 `Apply` 呼び出しは追加のロックなしに安全。
