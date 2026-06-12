# schema — 登録 schema に対する payload 検証
> 日本語版 — English: [README.md](README.md)

schema レジストリのクライアント側コントラクト：`Validator` — `Validate(ctx, payload, ref vc.SchemaRef) error`。プロセスの optional な入力・出力 schema 検査は両方ともこの 1 つのインターフェースで表現する。validator を注入しなければ検査はスキップされる。

## 規約

- `SchemaRef` の解決（schema 文書の content-addressed な取得）は実装の関心事であり、呼び出し側の関心事ではない。
- 実装は subpackage に置く（`resolver/` と同パターン）：
  - `local/` — ファイルシステム / 埋め込みの schema store（PoC fixture、組織内 deployment）。config / cmd 配線の作業とともに着地する。
  - レジストリベースのクライアント（SchemaService）は network 層とともに着地する。
- verifier 側の resolve-and-compare 義務（`credential.schema-ref`）は、verifier 改修時に本パッケージを共用する。
