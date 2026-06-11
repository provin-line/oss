# api/protobuf — プロトコル定義
> 日本語版 — English: [README.md](README.md)

dplaax プロトコルの proto 定義。`buf` で管理。

## 名前空間

```
dplaax.did.v1       DIDService, SignerService + DID Document / 委任メッセージ
dplaax.schema.v1    SchemaService（不変、追記専用レジストリ）
dplaax.chain.v1     ChainService（オペレーター向け）+ ChainPeerService（インターネット公開, L2 認証）
dplaax.vc.v1        VCResolverService（来歴チェーン解決）
dplaax.pipeline.v1  トランスポートメッセージのみ（PipelinePassCredential のワイヤー形式、設定）
```

## 規約

- 生成コードは `gen/` 配下に**コミット済み** — コントリビューターは `buf` なしでビルドできる。再生成は `make proto`。
- 認可ポリシーはメソッドオプション（リソース + アクション）で RPC に宣言され、サーバーサイドのインターセプターが強制する（L1）。`ChainPeerService` の RPC には L1 ポリシーを持たせず、埋め込みの `AuthProof` メッセージ（L2 ワイヤー署名）のみで認証する。
- VC ボディのワイヤーメッセージは、精度を失わずに正規化を往復できなければならない。変換は正規ハッシュの比較でガードされる（`canon` 参照）。
- `dplaax.pipeline.v1` の `syntax = "proto3"` は意図的・規範的な選択である：provin profile の「空 / 不在 payload」の論証は proto3 の implicit field presence に依拠する。editions への移行は presence 意味論を変えるため、tooling の更新ではなく profile の議論である。
- pipeline envelope は credential を構造化メッセージではなく JSON 文書（bytes）として運ぶ：unknown signed-scope member は canonical レベルで byte 忠実に transport を生き残らなければならず、field projection ではこれを守れない。
