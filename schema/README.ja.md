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

JSON Schema の library は `internal/jsonschema` で、`santhosh-tekuri/jsonschema` の写しに patch を足したもの: 手間の予算、読めない数で upstream が panic する所の誤り、schema の大きさにほぼ線形の時間での compile（`uniqueItems` が長い前置きを共にする object の名前を並べる所では、最大で log n 倍） と、予算の中での metaschema の確かめ（その README を参照）。断る時の誤りの文は、どの限りで断ったかを書く。

- schema と payload の数: 256 bytes まで、指数の部分（`e` か `E` の後）は ±400 の内。library は数を正確な有理数で読み、その手間は指数とともに増える。payload では予算がそれを数え、schema を compile する所ではこの限りが手間を小さく保つ。
- schema: 入れ子は 64 段まで（object・配列・scalar のどれも 1 段）。object と真偽値は 4,096 と、schema の 8 bytes ごとに 1 つまで（どこにあっても数える。`default` や例の中も。`$ref` でどれも subschema になりうるため）。JSON pointer と URL の長さの和は、2^16 bytes と、schema の 1 byte ごとに 16 bytes まで（値の pointer は、library が location に持つ形、URL 向けに escape した長さで数える。id と参照（`$id`、draft-04 の `id`、`$ref`、`$dynamicRef`、`$recursiveRef`）が解く URL も、escape した長さで数える）。配列の番号を RFC 6901 の形（`0` か、0 で始まらない数字の並び）で書いていない pointer（`00`、`+0`、`-0`、`01`）による参照は、見つからないとして断る。metaschema との確かめは、2^20 段と、schema の 1 byte ごとに 16 段の手間の予算の中で行う。library の subschema 1 つあたりの手間は深さとともに増え、object と真偽値ごとに約 1 KB の subschema を、pointer と location とともに持つ。登録した schema は compile した形で持ち続ける。この限りの内で、1 MiB の schema が compile した形で持ち続けるのは約 170 MB まで（測った最悪の形で 127 MB、compile は約 0.5 s 以内。metaschema の予算で断る schema は約 0.8 s 以内に断る）。SchemaStore の schema は、入れ子が最大 23 段、object と真偽値は 40 bytes に 1 つまで、pointer と URL は 1 byte あたり最大 4.03 bytes、metaschema との確かめは予算の 11.5% まで。
- payload: 入れ子は 512 段まで。library の 1 段あたりの手間は、入れ子とともに増える。
- schema に対する payload: 2^20 段と、payload の 1 byte ごとに 16 段の、手間の予算の中で確かめる。1 段は、およそ schema を値に 1 回当てること、または library が読む、比べる、たどる 1 byte、property、item、値の 1 つ（`internal/jsonschema` に書いてある）。普通の schema 2 つで 1 byte あたり 1.0 と 1.6 段だった（その `BenchmarkValidateWithBudget`）。1 つの値に重ねた schema（allOf、$ref）はもっと要る。それより手間の要る payload は断る。schema を互いの中に 10,000 段より深く当てる payload も断る（library の `MaxNesting`）。予算が数えないもの（入れ子とともに増える 1 段の手間、文字列の長さを越える format の確かめ）は、上の深さの限りか文字列の長さで限る。
