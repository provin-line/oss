# hoconconfig — 3 層 HOCON 設定

> 日本語版 — English: [README.md](README.md)

このリポジトリ内のすべてのバイナリで使用される層化設定ローダー。

## 層（優先度の低い順）

1. **Reference** — パッケージのデフォルト値。埋め込みの `reference.conf` ファイル（`go:embed` + `RegisterPackageReference`）を通じて `init()` で登録される。
2. **Application** — オペレーターが提供する `config/application.conf`（任意）。
3. **Overlay** — 環境変数で指定されるファイル（任意。ネットワーク用: `CONFIG_OVERLAY`、プロセスバイナリ用: `CONFIG_FILE`）。

置換（`${...}`）はすべての層のマージ後に一度解決されるため、どの層も下位層で定義されたキーを参照できる。

## 厳守ルール: Go 側にデフォルト値を持たない

すべてのデフォルト値は `reference.conf` に存在する。Go コードは欠落したキーに対してフォールバック値をサイレントに代入しない。バイナリは起動時にオペレーターのオーバーライドを検証し、無効な値（例: 非正の間隔）に対して明示的に失敗する。

## API

```go
// RegisterPackageReference はパッケージの埋め込み reference.conf を init() 時に登録する。
// 同じ名前で重複登録した場合は ErrDuplicateReference をラップしてパニックする。
func RegisterPackageReference(name, content string)

// Load は登録済みの全 reference + オプションの config/application.conf (appDir 下) +
// オプションのオーバーレイファイル (overlayEnv 環境変数で指定) を連結して一度だけ
// パースする。環境変数が設定されているがファイルが読めない場合はエラー。未設定は正常。
func Load(appDir, overlayEnv string) (*Config, error)

func (c *Config) String(path string) (string, error)
func (c *Config) Int(path string) (int, error)
func (c *Config) Bool(path string) (bool, error)
func (c *Config) Duration(path string) (time.Duration, error)  // "250 ms", "5 s" など
func (c *Config) StringList(path string) ([]string, error)
func (c *Config) Has(path string) bool  // オプションブロック用

// センチネルエラー (すべて対象パスをラップして返される):
var ErrMissingKey, ErrTypeMismatch, ErrDuplicateReference error
```

マージ戦略: すべての層をプレーンテキストとして連結し、**一度だけ**パースする。
HOCON は後から出現するキーを優先し、ドキュメント全体で置換 (`${...}`) を解決するため、
どの層の置換も下位層で定義されたキーを参照できる。

## 既知の制限

**`null` 値**: `key = null` はドキュメント内に存在する — `Has` は `true` を返す。
型付きアクセサー（`String`、`Int` など）は `null` が文字列・整数などではないため
`ErrTypeMismatch` を返す。

**置換の自己参照**: 本来の HOCON は自己参照置換（`x = ${x}"-suffix"`）で
下位層の値を上位層で拡張できる。このライブラリはそのパターンで
substitution-cycle エラーを発生させる。
層をまたいで値を拡張するには、自己参照ではなく別のキー名を使うこと。
