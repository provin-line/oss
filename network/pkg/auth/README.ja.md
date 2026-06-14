# network/pkg/auth — L1 認可エンフォースメント (PEP)

> 日本語版 — English: [README.md](README.md)

ネットワーク層の認可**エンフォースメントポイント**。ポリシー判定もトークン発行も行わず、既存の [`o3co/protobuf.interceptors`](https://github.com/o3co/protobuf.interceptors) の ConnectRPC interceptor と設定済み verifier をサービスのハンドラに配線するだけ。

三層分離（dPLaaX auth スタック）:

| 層 | 場所 | 役割 |
|---|---|---|
| トークン発行 (authN) | `o3co/auth.provider` + provin.auth provider | DID-grant OAuth; no-scope identity JWT（`sub` = Owner DID）を発行 |
| 判定 (authz) | `o3co/auth.policy-verifier` + provin.auth `policy-verifier-dplaax-module` | PDP; `{resource, action}` をキーとする rule/attribute collector、DID 認識 |
| **エンフォースメント (authz)** | **本パッケージ** | PEP — proto の policy option を読み、PDP を呼び、許可/拒否 |

## 提供するもの

- `Interceptors(verifier) []connect.Interceptor` — ハンドラに載せる順序付きチェーン（`PolicyOptionInterceptor` → `VerificationInterceptor`）。順序は固定: option interceptor が context を埋めてから verification interceptor が読む。
- `NewVerifier(url, opts…) (endpoint.VerifierEndpoint, error)` — 本番 verifier（`auth.policy-verifier` REST クライアント）を構築。URL は明示的な `http://`/`https://` scheme 必須（fail-closed; 偶発的な平文を防ぐ）。テストは `endpoint.NewStaticEndpoint` を直接使う。
- `AuthConfig` + `LoadAuthConfig` — 型付き `provin.network.auth.*` 設定（`policy-verifier-url`）。起動時に fail-closed 検証（空/scheme なし → 起動エラー。未設定エンドポイントに対して認可を走らせない）。

## ポリシー宣言

認可ポリシーは RPC ごとに `.proto` の `o3co.authz.v1.policy` method option（`resource` + `action`、任意の `field_mappings`）で宣言する。**option の無い RPC はチェックされない** — descriptor テストが、保護対象サービスの全 RPC に注釈があることを保証するので、未保護 RPC はビルドで落ちる。

`ChainPeerService` は本層では意図的にエンフォースしない — L2（wireauth）で認証し、L1 では扱わない。
