# アーキテクチャ overview

provin は **dPLaaX プロトコル**の reference implementation（**wire profile `provin`**）— すべてのデータ変換を W3C Verifiable Credential として署名し、どの参加者も独立に検証できる線形 provenance chain を形成する、分散データパイプラインエンジンである。本ページは系の**平面（plane）と信頼層（trust layer）**の正本 — 部品の関係と、信頼がどこから来るかを記述する。naming・リポジトリ layout・依存方向則・library package カタログは[ルート README](../../README.md)、何がどこで動くかは [deployment.ja.md](deployment.ja.md) を参照。

## 2 平面、2 バイナリ

provin ノードは常に別々にデプロイされる 2 つのバイナリで構成される。1 つのバイナリにまとまることはない:

- **コントロールプレーン**（`cmd/network`） — registry・調整サービス群（DID registry、schema registry、signer、VC resolver、audit、tlog、chain manager）。1 つの HTTP listener 上の ConnectRPC handler として提供。状態は DB-free: data dir 配下の YAML record と append-only file log（[deployment.ja.md — 永続状態](deployment.ja.md)）。設定に pipeline loop が 1 つでも宣言されていれば起動を拒否する。
- **データプレーン**（`cmd/pipeline`） — 共有 NATS 接続上で動く 0 個以上の**パイプラインループ**（[processes.ja.md](processes.ja.md) の process peer 型）。ループはイベントを消費・変換・署名・emit し、コントロールプレーンの証拠面（credential、log checkpoint、audit verdict）に WIRE client としてのみ到達する。loop がゼロの設定では起動を拒否し、自前の in-process registry は一切持たない。

2 つのバイナリは互いに import しない（AGENTS.md レイヤールール 2）— wire 越しにのみやり取りし、同一ホスト上でも別ホスト上でも動く。registry の存在に pipeline ノードは不要であり、pipeline ノードが検証するには解決可能な registry が必要。合成の全体像は [deployment.ja.md](deployment.ja.md) を参照。

## 信頼層

auth stack は 3 つの関心事を分離する。各層は異なる問いに答え、どの層も他層の代替にならない（enforcement のカタログは [network/README.ja.md](../../network/README.ja.md)、プロトコル視点は [protocol/auth.ja.md](../protocol/auth.ja.md)）:

| 層 | 問い | 機構 |
| --- | --- | --- |
| **L1 — API アクセス** | この呼び出し元はこの RPC を呼んでよいか？ | bearer token + 外部 policy decision point (PDP)。per-RPC interceptor で強制 |
| **L2 — peer wire 証明** | この名前の peer が本当にこの要求を送ったか？ | canonical view への per-RPC Ed25519 署名、nonce replay 防御、DID 解決鍵 |
| **L3 — provenance** | このデータの履歴は真正か？ | credential chain そのもの: Data Integrity proof、content-addressed link、transparency log、audit verdict |

load-bearing な性質は **L3 の信頼がどこから来ないか**にある: provenance chain を検証する relying party が信頼するのは署名・content hash・chain 構造であって、bytes を運んだ transport でも、たまたまそれを載せた L1/L2 セッションでもない。この独立性の主張は意図的に狭い: 対象は**暗号学的 provenance 検証**（credential 署名・content hash・chain 構造）に限る。peer 認可・relationship evidence・payload 可用性・audit 完全性には及ばない — それらは L2 と、[audit-obligations.ja.md](../concepts/audit-obligations.ja.md) の運用上の証拠保全義務に依存する。

## 検証モデル

リアルタイム経路が検証するのは **adjacent**（直前リンク）のみ（process 毎のポリシーで fail-closed — [processes.ja.md](processes.ja.md)）。full-chain 検証は意図的に非同期: audit runner が consumed head ごとの chain をローカルストアから組み立て、per-head verdict を記録し、AuditService が提供する。これにより relay 経路は速く保たれ、audit カバレッジは inline の副作用ではなく、検分可能で永続的な記録になる。

## 次に読む

| トピック | ドキュメント |
| --- | --- |
| Process peer カタログ（Chained / Source / Sink / Custom） | [processes.ja.md](processes.ja.md) |
| デプロイ形態・設定の罠・health・metrics | [deployment.ja.md](deployment.ja.md) |
| Service API 面と endpoint 導出 | [../protocol/services.ja.md](../protocol/services.ja.md) |
| auth 層 L1/L2 のプロトコル視点 | [../protocol/auth.ja.md](../protocol/auth.ja.md) |
| `did:dplaax` method 仕様 | [../did/method.ja.md](../did/method.ja.md) |
| 証拠保全義務 | [../concepts/audit-obligations.ja.md](../concepts/audit-obligations.ja.md) |
| 用語集 | [../GLOSSARY.ja.md](../GLOSSARY.ja.md) |
