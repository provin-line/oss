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

JSON Schema の library は `internal/jsonschema` で、`santhosh-tekuri/jsonschema` の写しに、手間の予算と、読めない数で upstream が panic する所の誤りを足したもの（その README を参照）。断る時の誤りの文は、どの限りで断ったかを書く。

- schema と payload の数: 256 bytes まで、指数の部分（`e` か `E` の後）は ±400 の内。library は数を正確な有理数で読み、その手間は指数とともに増える。payload では予算がそれを数え、schema を compile する所ではこの限りが手間を小さく保つ。
- payload: 入れ子は 512 段まで。library の 1 段あたりの手間は、入れ子とともに増える。
- schema に対する payload: 2^20 段と、payload の 1 byte ごとに 16 段の、手間の予算の中で確かめる。1 段は、およそ schema を値に 1 回当てること、または library が読む、比べる、たどる 1 byte、property、item、値の 1 つ（`internal/jsonschema` に書いてある）。普通の schema 2 つで 1 byte あたり 1.0 と 1.6 段だった（その `BenchmarkValidateWithBudget`）。1 つの値に重ねた schema（allOf、$ref）はもっと要る。それより手間の要る payload は断る。schema を互いの中に 10,000 段より深く当てる payload も断る（library の `MaxNesting`）。予算が数えないもの（入れ子とともに増える 1 段の手間、文字列の長さを越える format の確かめ）は、上の深さの限りか文字列の長さで限る。
