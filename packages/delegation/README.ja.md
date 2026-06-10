# packages/delegation — 委任クレデンシャル
> 日本語版 — English: [README.md](README.md)

Owner DID が Pipeline または Process DID へ権限（スコープ付き、例: `pipeline:operate`・`process:sign`）を委任することを表明する、オーナー署名付き `DelegationCredential`。

## 規約

- 発行者は `delegatedBy` と一致しなければならない。検証時には発行者の DID Document を解決し、オーナーのアサーションキーに対して証明を検証する。
- 委任クレデンシャルは委任先 DID とともにレジストリに永続化され、`ResolveDelegation` 経由で提供される。
- 証明のメカニズムは `packages/vc`（`CreateProof`・`VerifyProof`）を再利用する — このパッケージが所有するのは委任固有の形状とルールのみである。
