# conformance/ — provin profile 適合性 artifact
> 日本語版 — English: [README.md](README.md)

**provin wire profile** の機械検証可能な事実をデータとして固定し、
`go test ./conformance/` が本実装に対して実行する。

**本ディレクトリに規範の散文は置かず、規範の再表現もしない。** SoT は以下:

| 規範 | SoT |
|---|---|
| dPLaaX protocol 規則（claim 文法・接地・開世界デフォルト等） | `dplaax.spec_draft` の rule catalog（`rules/` + `schemas/` + `vectors/`） |
| provin claim registry と各 claim の意味（closed / conformant-closed / open） | [vc/credential.go](../vc/credential.go)（`TransformationClaim` registry の doc comment）+ [vc/README.ja.md](../vc/README.ja.md) |
| provin profile context 文書（byte 単位で正規） | [vc/contexts/provin-v1.jsonld](../vc/contexts/provin-v1.jsonld) |

## vector が固定するもの

- `vectors/claim-*.json` — registry の各 claim について: wire トークンが文法適合
  であること、実装が profile の `@context` リストを正確に emit すること、接地
  チェックが受理すること、展開が固定された語彙 IRI に一致すること
  （claim の同一性 = (接地 URL, label) の組）。
- `vectors/context-001.json` — profile context 文書の byte 台帳: sha256、
  文書が担う prefix 接地、`@protected`。文書バイトの変更は意図的な行為であり、
  同一変更内で台帳を更新しなければ harness が fail する。

vector の形状は `dplaax.spec_draft` の vector 規約に従う。`instantiates` field は
その vector が行使する protocol rule id への参照 — 情報提供であり、protocol 側
vector 集合への所属を主張するものではない。

claim ごとの*意味*は署名者による宣言（帰責のための claim であり、機械検証される
性質ではない）ため、vector には意図的に**含めない** — ここに複製すると第二の
SoT が生まれる。

## 将来の受け皿

protocol 自身の conformance vector（`dplaax.spec_draft` `vectors/`、78 本）の
cross-repo 消費は、harness が profile 事実以外の family に拡張された時点で
ここに置く。
