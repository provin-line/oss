# dplaax — did:dplaax メソッド
> 日本語版 — English: [README.md](README.md)

profile の T1 native DID method: パース・セグメント文法・意味論的バリデーション。**credential 発行面に許される唯一の method** であり、`PipelinePassCredential` の `issuer` の背後にある Process / Pipeline / Owner DID はすべて `did:dplaax`。method 非依存の DID Document モデルと dispatch は親 `did` package に住む。

## 構文

```text
did:dplaax:{registry}:{accountType}:{accountId}[:{resourcePath}]
```

- `registry` は**ドメイン名**（例: `poc.dplaax.io`）であり、解決 URL はここから導出される（`https://{registry}/did/...`）。環境（PoC・本番）はここで表現し、メソッド名には含めない — W3C DID Core §3.1 はメソッド名を `[a-z0-9]` に制限している。
- 階層: Owner DID（リソースパスなし）→ Pipeline DID（`:pipeline:{id}`）→ Process DID（`:pipeline:{id}:process:{id}`）。

## 規約

- **パーサーは構文のみを担う。** 意味的な分類は `IsOwner`・`IsPipeline`・`IsProcess` メソッドが担う。新しいリソース型を追加する際は分類メソッドと既知パターンバリデータのケースを追加すればよく、パーサー自体は変更しない。
- すべてのセグメントは安全セグメントルール（`[a-zA-Z0-9._-]+`、ドットのみのセグメントは不可）に対してバリデーションされる。これにより DID セグメントをストレージパスの構築に使用してもパストラバーサルのリスクがない。コンシューマはパスを組み立てる前に exported された安全性チェックを必ず呼び出すこと。
