# dplaax — did:dplaax メソッド
> 日本語版 — English: [README.md](README.md)

profile の T1 native DID method: パース・セグメント文法・意味論的バリデーション。**credential 発行面に許される唯一の method** であり、`PipelinePassCredential` の `issuer` の背後にある Process / Pipeline / Owner DID はすべて `did:dplaax`。method 非依存の DID Document モデルと dispatch は親 `did` package に住む。

## 構文

```text
did:dplaax:{registry}:{accountType}:{accountId}[:{resourcePath}]
```

- `registry` は**ドメイン名**（例: `poc.dplaax.io`）であり、解決 URL はここから導出される（`https://{registry}/did/...`）。環境（PoC・本番）はここで表現し、メソッド名には含めない — W3C DID Core §3.1 はメソッド名を `[a-z0-9]` に制限している。
- 階層: Owner DID（リソースパスなし）→ Pipeline DID（`:pipeline:{id}`）→ Process DID（`:pipeline:{id}:process:{id}`）。

## 登録と identity binding

Owner DID は識別子に名指しされた federation registry（PoC では `poc.dplaax.io`）が発行する。登録の検証水準 — T1 特性である組織検証 — は federation governance の事項であって protocol ではない: `did:web` 等の対外 identity の支配証明は自然な入力だが、domain 支配単体は T3 級の証拠であり組織検証の代替にはならない。

申請者が登録時に対外 DID を提出した場合、registry は束縛と、その時点で解決した対外 DID 文書の snapshot を append-only lifecycle log に記録する。これにより Owner identity binding（GLOSSARY 参照）は自己主張ではなく**誕生時点から registry-witnessed** となり、この snapshot が後の domain 乗っ取りを検出する監査側の照合基準になる。対外 domain の rotation・消失は同じ log に記録される lifecycle event であり、attribution には一切触れない。

registry domain 自体は discovery 機構であって trust anchor ではない: 検証者が最終的に依拠するのは registry の append-only log（signed checkpoint）であり、chain の検証はそもそも registry の生存に依存しない — chain link は content commitment である。

## 規約

- **パーサーは構文のみを担う。** 意味的な分類は `IsOwner`・`IsPipeline`・`IsProcess` メソッドが担う。新しいリソース型を追加する際は分類メソッドと既知パターンバリデータのケースを追加すればよく、パーサー自体は変更しない。
- すべてのセグメントは安全セグメントルール（`[a-zA-Z0-9._-]+`、ドットのみのセグメントは不可）に対してバリデーションされる。これにより DID セグメントをストレージパスの構築に使用してもパストラバーサルのリスクがない。コンシューマはパスを組み立てる前に exported された安全性チェックを必ず呼び出すこと。
