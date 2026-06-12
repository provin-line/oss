# provenance — 共有 VC 署名・検証メカニクス
> 日本語版 — English: [README.md](README.md)

`vc` の VC 機構に対するプロセス向けインターフェース：

- `ChainedSigner` — `Sign(ctx, payload, inputHash, outputHash, predecessor)`；Chained Process のためのチェーン保持 credential を発行する（`previousCredential` = predecessor の content hash）。predecessor は**この event の検証済み入力 credential** であり、runtime が呼び出しごとに渡す。audit-reachable な deployment（config 駆動）では、消費した conformant set へのソースコミットメント（`vc.SourceCommitment` — [../source/README.md](../source/README.md) 参照）を signer が付与する — stateless な 1:1 プロセスではその set は正確に {predecessor}（all-consumed 意味論）。
- `SourceSigner` — `Sign(ctx, payload, inputHash, outputHash)`；Source Process のための FirstDrop（新しいチェーン起点）を発行する。audit-reachable な集約が必要とする consumed-set の経路は aggregate runtime の着手時に gate する。
- `Verifier` — `Verify(ctx, *Credential) (*VerifyResult, error)`；各軸の最弱リンクで求めた信頼度 verdict を返す。
- `ChainVerifier` — `VerifyChain(ctx, head) (*VerifyResult, error)`；`VerificationFull` を宣言するプロセス（sink、観測ツール）向けの全チェーン検証。content address によるチェーン取得は実装の関心事。

署名能力は chain 挙動で分割されている（`vc.Builder` の明示的メソッド分割と同型）：プロセスは宣言した `contract.ChainBehavior` と一致する能力だけを持って構築されるため、Chained Process が FirstDrop を発行できないことを型システムが強制する。signer はチェーン状態を持たない — チェーンリンクが指すのは event の入力 credential であり、プロセスが直前に発行した credential では決してない。

## vcdid/ — DID/VC バックの実装

- 署名はレジストリの SignerService に ConnectRPC 経由で委譲する（KMS モデル）；データはローカルで事前ハッシュされ、`sha256:` ダイジェストのみがワイヤーを渡る。
- チェーンに関して stateless：predecessor は呼び出しごとに到着する。1 つの provider 値が両方の signer 能力を実装し、ロックなしでゴルーチン間共有できる。
- 検証は `resolver` 経由で発行者 DID を解決し、リモート署名者の規約に合わせて SHA-256 で事前ハッシュする。

これらのパッケージは**プロセスのセマンティクスを持たない** — 署名または検証を行うすべてのプロセス型が使用する。
