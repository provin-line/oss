# packages/hoconconfig — 3 層 HOCON 設定
> 日本語版 — English: [README.md](README.md)

このリポジトリ内のすべてのバイナリで使用される層化設定ローダー。

## 層（優先度の低い順）

1. **Reference** — パッケージのデフォルト値。埋め込みの `reference.conf` ファイル（`go:embed` + `RegisterPackageReference`）を通じて `init()` で登録される。
2. **Application** — オペレーターが提供する `config/application.conf`（任意）。
3. **Overlay** — 環境変数で指定されるファイル（任意。ネットワーク用: `CONFIG_OVERLAY`、コンポーネントバイナリ用: `CONFIG_FILE`）。

置換（`${...}`）はすべての層のマージ後に一度解決されるため、どの層も下位層で定義されたキーを参照できる。

## 厳守ルール: Go 側にデフォルト値を持たない

すべてのデフォルト値は `reference.conf` に存在する。Go コードは欠落したキーに対してフォールバック値をサイレントに代入しない。バイナリは起動時にオペレーターのオーバーライドを検証し、無効な値（例: 非正の間隔）に対して明示的に失敗する。
