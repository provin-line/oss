# packages/did — did:dplaax メソッド
> 日本語版 — English: [README.md](README.md)

`did:dplaax` メソッドにおける DID のパース・DID Document モデル・意味論的バリデーション・公開鍵抽出。

## 構文

```
did:dplaax:{registry}:{accountType}:{accountId}[:{resourcePath}]
```

- `registry` は**ドメイン名**（例: `poc.dplaax.io`）であり、解決 URL はここから導出される（`https://{registry}/did/...`）。環境（PoC・本番）はここで表現し、メソッド名には含めない — W3C DID Core §3.1 はメソッド名を `[a-z0-9]` に制限している。
- 階層: Owner DID（リソースパスなし）→ Pipeline DID（`:pipeline:{id}`）→ Process DID（`:pipeline:{id}:process:{id}`）。

## 規約

- **パーサーは構文のみを担う。** 意味的な分類は `IsOwner`・`IsPipeline`・`IsProcess` メソッドが担う。新しいリソース型を追加する際は分類メソッドと既知パターンバリデータのケースを追加すればよく、パーサー自体は変更しない。
- すべてのセグメントは安全セグメントルール（`[a-zA-Z0-9._-]+`、ドットのみのセグメントは不可）に対してバリデーションされる。これにより DID セグメントをストレージパスの構築に使用してもパストラバーサルのリスクがない。コンシューマはパスを組み立てる前に exported された安全性チェックを必ず呼び出すこと。
- **DID Document からの公開鍵抽出はここで一元管理する。** コンシューマが独自にコピーを持つことはない（前バージョンのコードベースで知られていたドリフトの発生源）。

## 実装予定の内容

- `DID` 型 + `Parse` / 分類メソッド / バリデーション
- `DIDDocument`・`VerificationMethod`・`ServiceEndpoint` モデル
- `ExtractPublicKey(doc, keyID)` — 検証リレーションシップチェックを含む JWK（OKP/Ed25519）抽出
