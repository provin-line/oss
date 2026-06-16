# signer — KMS モデル署名サービス
> 日本語版 — English: [README.md](README.md)

`keystore` を基盤とした Ed25519 署名。秘密鍵は RPC 境界を越えない; パイプラインプロセスとピアは鍵ではなく DID を保持し、レジストリプロセスが鍵素材を保持して署名だけを返す。

Proto: `dplaax.signer.v1`（`SignerService`）。

2 つの署名ドメイン、2 つのコンシューマー:

| RPC | Input | Output | 鍵 | Authz | Used by |
|---|---|---|---|---|---|
| `Sign` | 生バイト | 生 Ed25519 署名 | `#signing` | `signer:sign-vc` | VC プルーフ生成（パイプラインプロベナンス） |
| `SignRaw` | 生バイト | 生 64 バイト Ed25519 署名 | `#auth` | `signer:sign-wire` | L2 ワイヤー署名（chainmanager wireauth） |

## 生バイト seam

両 RPC は committed な `crypto.Signer` seam の薄いトランスポート: **生**の署名対象バイトを受け取り、**生**の Ed25519 署名を返す。出力エンコーディングは呼び出し側の責務 — `vc.CreateProof` は proof `hashData` を渡し、返ってきた署名に base58btc マルチベースを自分で適用する。L2 ワイヤー署名は生 64 バイト署名をそのまま使う。サービスは入力を `sha256:<hex>` 事前ハッシュに、出力をマルチベースに再フレームしない（それをやると client 側で decode 往復が発生して無駄）。

## 2 RPC、2 ドメイン

`Sign` と `SignRaw` は暗号的に同一（供給バイトに対する Ed25519）。分ける理由は、2 つの署名ドメインに**別々の認可ポリシー**を持たせるため（オペレータは wire 署名を許可せず VC 署名だけを許可できる）、かつ各々を**鍵リレーションシップに束縛**するため: `Sign` は `key_id == "signing"`（`#signing` assertionMethod 鍵）のみ、`SignRaw` は `key_id == "auth"`（`#auth` authentication 鍵）のみを受け付ける。クロスした `key_id` は拒否 — VC エンドポイントで auth 鍵を使う（逆も）ことはできない。

## 利用方法

production の `crypto.Signer` は `client.New(SignerServiceClient)` — keyID で dispatch し（server 束縛の逆: `signing` → `Sign`、`auth` → `SignRaw`）、生署名を返す。コンシューマー（pipeline runtime、chainmanager wireauth）はこのアダプタ / コンシューマー側の絞り込みインターフェースを通じて依存する — サービスパッケージ自体には依存しない（サービス間インポートサイクルを回避）。`client` パッケージは生成 client・`crypto`・`keystore` 鍵 ID 契約のみを import する。

## プロトコル必須ではなく deployment パターン

署名 seam をこのネットワークサービスで前置するのは **KMS deployment パターン**（鍵をレジストリに集約）。シングルプロセス deployment は代わりに**インライン署名**（`crypto/ed25519.NewSigner` でローカル鍵）してもよく、SignerService を一切公開しなくてもプロトコル的に有効なプルーフを生成できる。provin のリファレンス deployment は KMS パターンに commit する; proto は「もし動かすなら」の wire 形を標準化する。
