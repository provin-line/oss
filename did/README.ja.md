# did — DID ドメイン（method 非依存）
> 日本語版 — English: [README.md](README.md)

method 非依存の DID 層: 全 consumer が共有する W3C DID Document モデル、公開鍵抽出、method dispatch プリミティブ（`MethodOf`）。ここはいかなる method の識別子文法も知らない。

## 構成

| 場所 | 責務 |
|---|---|
| 本 package | `DIDDocument` / `VerificationMethod` / `ServiceEndpoint` モデル、`ExtractPublicKey`、`MethodOf`（W3C DID Core 構文の dispatch） |
| `dplaax/` | `did:dplaax` method — profile の T1 native method であり、**credential 発行面に許される唯一の method** |

method は subpackage に住む。web アンカー系（`did:webvh`、`did:web`）は、認証面または external-DID-source ingestion pattern が必要とした時点で `dplaax/` の隣に置かれる。**非発行面**（認証、external-DID-source ingestion）にどの method を許すかは deployment policy であり（GLOSSARY の DID method tiers 参照）、型レベルの契約ではない。credential 発行面は profile によって `did:dplaax` に固定される。

method 横断の identity — did:dplaax の Owner と `did:web` 等の対外 identity が同一当事者であること — は **Owner identity binding** パターンで扱う（双方向 `alsoKnownAs`、Owner 登録時に提出されれば registry-witnessed。GLOSSARY 参照）。束縛は attribution を動かさず、equivalence registry は存在しない。本 package に equivalence を解決するものは無い。

## 規約

- **DID Document からの公開鍵抽出はここで一元管理する。** consumer が独自コピーを持つことはない（前身コードベースで知られた drift 源）。
- **dispatch は fail-closed。** `MethodOf` は `did:` + 小文字 `[a-z0-9]` の method 名 + 非空 method-specific id 以外をすべて拒否する。未検証の method 名で routing するのはバグである。
