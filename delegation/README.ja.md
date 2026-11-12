# delegation — 委任クレデンシャル
> 日本語版 — English: [README.md](README.md)

Owner DID が Pipeline または Process DID へ権限を委任することを表明する、オーナー署名付き `DelegationCredential`。provin プロファイルは**スコープなし**: スコープを載せた委任は fail-closed で拒否する（spec の `delegation.scope` は他の wire プロファイル向けに scope を任意として残しており、provin は不使用を選択 — `delegation.go` 参照）。

## 規約

- 発行者は `delegatedBy` と一致しなければならない。検証時には発行者の DID Document を解決し、オーナーのアサーションキーに対して証明を検証する。
- 委任クレデンシャルは委任先 DID とともにレジストリに永続化され、`ResolveDelegation` 経由で提供される。
- 証明のメカニズムは `vc`（`CreateProof`・`VerifyProofWithContract`）を再利用する — このパッケージが所有するのは委任固有の形状とルールのみである。
- `Verify` は断りのそれぞれに、外れた確かめの種類の sentinel を 1 つ付ける（`errors.Is`）: `ErrMalformed`、`ErrOwnerBinding`、`ErrProofPolicy`、`ErrScoped`、`ErrIssuerNotFound`、`ErrSignatureInvalid`、`ErrSignatureUnestablished`（呼ぶ側がやり直してよいのはこれだけ）。`VerifyFor` は、別の identity に向けて出された委任を `ErrNotForIdentity` で断り、ほかは `Verify` の断りを返す。どの確かめで外れたかは、error の文が言う。
