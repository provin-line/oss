# provenance — 共有 VC 署名・検証メカニクス
> 日本語版 — English: [README.md](README.md)

`packages/vc` の VC 機構に対するコンポーネント向けインターフェース：

- `Provider` — `Sign(ctx, payload, inputHash, outputHash) (*Credential, error)`；プロセスごとのチェーン状態（`previousCredential` リンク）を管理し、audit-reachable conformance class で deploy された境界の場合（config 駆動、Origin Source に限らない — chain-preserving は先行イベントを含む全消費分に commit する）はソースコミットメント（`vc.SourceCommitment` — [../originsource/README.md](../originsource/README.md) 参照）も管理する。
- `Verifier` — `Verify(ctx, *Credential) (*VerifyResult, error)`；各軸の最弱リンクで求めた信頼度 verdict を返す。

## vcdid/ — DID/VC バックの実装

- 署名はレジストリの SignerService に ConnectRPC 経由で委譲する（KMS モデル）；データはローカルで事前ハッシュされ、`sha256:` ダイジェストのみがワイヤーを渡る。
- チェーン状態（`lastVC`）はミューテックスで保護されている — プロバイダは複数ゴルーチン間で共有可能。
- 検証は `packages/resolver` 経由で発行者 DID を解決し、リモート署名者の規約に合わせて SHA-256 で事前ハッシュする。

これらのパッケージは**コンポーネントのセマンティクスを持たない** — 署名または検証を行うすべてのコンポーネント型が使用する。
