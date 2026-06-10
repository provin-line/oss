# network/pkg/auth — L1 認証 & 認可
> 日本語版 — English: [README.md](README.md)

オペレーター向け RPC に対する Bearer JWT 検証と RBAC 適用。

- `JWTVerifier` インターフェースには 2 つの実装がある: JWKS（Ed25519、発行者フェッチ・キャッシュ済み）と HS256（共有シークレット）。モードは設定で選択; `"none"` はローカル開発環境専用。
- Connect インターセプターがトークンを抽出して検証し、サブジェクトをコンテキストに格納する; RPC ごとの適用はプロトコルで宣言されたポリシーオプションを参照する。
- **ChainPeerService のルートは意図的に L1 ルールから除外されている** — それらは L2（wireauth）のみで認証される。ここに追加することはバグであり、セキュリティ強化ではない: 見かけ上のセキュリティレイヤーで組織間ピアリングを壊す結果になる。
- **トークン発行は本パッケージの責務ではない。** L1 トークンは外部の provin.auth サービス（別リポジトリ; 系統: o3co.auth.provider スタック上の dplaasio/auth）が DID grant `urn:dplaax:oauth:grant-type:did` で発行する — クライアントは Owner DID の制御を証明し、identity assertion JWT（`sub` = Owner DID、scope なし）を受け取る。本パッケージはその検証（JWKS）と RPC ごとのポリシー適用のみを行う。
