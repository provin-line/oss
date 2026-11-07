# schema — 登録 schema に対する payload 検証
> 日本語版 — English: [README.md](README.md)

schema レジストリのクライアント側コントラクト：`Validator` — `Validate(ctx, payload, ref vc.SchemaRef) error`。プロセスの optional な入力・出力 schema 検査は両方ともこの 1 つのインターフェースで表現する。validator を注入しなければ検査はスキップされる。

## 規約

- `SchemaRef` の解決（schema 文書の content-addressed な取得）は実装の関心事であり、呼び出し側の関心事ではない。
- 実装は subpackage に置く（`resolver/` と同パターン）：
  - `local/` — ファイルシステム / 埋め込みの schema store（PoC fixture、組織内 deployment）。config / cmd 配線の作業とともに着地する。
  - レジストリベースのクライアント（SchemaService）は network 層とともに着地する。
- verifier 側の resolve-and-compare 義務（`credential.schema-ref`）は、verifier 改修時に本パッケージを共用する。

## 限り

JSON Schema の library（`santhosh-tekuri/jsonschema`）は数を正確な有理数で読み、自分の手間を限らない。そのため、ここでの確かめが library に渡すものを限る。断る時の誤りの文は、どの限りで断ったかを書く。

- schema と payload の数: 256 bytes まで、指数の部分（`e` か `E` の後）は ±400 の内。
- payload: 入れ子は 512 段まで。
- schema に対する payload: payload の JSON の値の数 × schema の `enum` の項目と `const` の数が 2 000 000 まで。小さい payload は大きい `enum` を、大きい payload は小さい `enum` を使える。

これらの限りは、library の手間のいくつかの形を断つ。すべての schema と payload について手間を限るものではなく、それには library の中の手間の予算が要る。予算は入れる予定で、入ったらその設定に替える。
