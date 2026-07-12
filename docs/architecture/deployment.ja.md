# デプロイメント
> 日本語版 — English: [deployment.md](deployment.md)

provin ノードのデプロイ形態と、**load-bearing な**（間違えるとノードは正常に起動するのに仕事ができない）少数の設定判断について。設定キーの正典は各 package の `reference.conf` — 本ページはそれらが局所的にしか説明できない横断的な判断を扱う。

## デプロイ形態

| 形態 | 構成 | 参照 |
| --- | --- | --- |
| 単一ホスト評価 | Docker Compose で全部を 1 ホストに: node + 実 auth スタック（auth.provider、policy-verifier）+ NATS、trust material は provision | [`deploy/quickstart/`](../../deploy/quickstart/README.md) |
| 単一組織 production | レジストリごとに 1 つの `standalone` ノード、外部 PDP、オペレーター管理の NATS trust material | 本ページ |
| 組織間フェデレーション | 組織ごとに 1 ノード。NATS account 境界が export/import seam を運び、peer 間は ChainPeerService（L2 wireauth） | [`network/README.ja.md`](../../network/README.ja.md) |

ノードは単一バイナリ（`cmd/standalone`）: HTTP コントロールプレーン（ConnectRPC サービス + 公開 DID 解決 + health エンドポイント）とデータプレーン（pipeline loop）が 1 プロセス・1 つの signal-cancelled context で動く。

## Load-bearing な設定

### 1. `resolver-base-url` + `dev.allow-loopback`（単一ホスト構成）

credential を検証するノードは、発行者の DID document を解決する。デフォルトの解決 URL は DID の registry セグメントから `https://{registry}` として導出される — 単一ホスト構成ではノード自身がその registry なので、これは loopback / private アドレスに解決される名前を指す。すると SSRF ガード（`network/pkg/core`、fail-closed の public-internet-only 姿勢）が**ノード自身の解決をブロック**する: 発行者を登録はできるのに、その署名を検証できないノードになる。

単一ホスト構成では以下 2 キーを必ずセットで設定する:

- `provin.network.chain.nats.resolver-base-url` — DID 解決が実際にこのノードへ届く URL（compose ネットワーク内なら例: `http://node:8443`）。
- `provin.network.core.dev.allow-loopback = true` — ガードにそれを許可させる。**設計上 dev 専用**: 複数ホストの production は実 DNS 名を使い、`allow-loopback` はデフォルトの `false` のまま。

quickstart はこの組合せを配線済み。自前で compose を組むなら最初にコピーすべき箇所。

### 2. broker の account claims キャッシング（接続後の grant）

NATS operator mode は account の接続時（または JWT 失効時）に account JWT を解決する。cross-account grant（`chain subscribe` の背後の export/import seam）はこの account JWT の**中に**入っている — つまりどちらかの account が接続した**後に**発行された grant は、claims が再読込されるまで broker から見えない。プロビジョニングが生成する無期限 JWT では「失効時の再読込」は永遠に来ない。

運用上の帰結:

- 稼働中スタックに grant を発行したら、更新済み claims を broker に push（`$SYS.REQ.CLAIMS.UPDATE`）するか broker を再起動して再読込させる。e2e ハーネスは push を行うが、production ノードはまだ自動では行わない（roadmap 項目: live claims push）。
- dir resolver 構成でも同じ性質: resolver ディレクトリに新しい JWT ファイルを置いても、接続済み account には反映されない。

見落とした時の症状: `chain subscribe` は成功する（コントロールプレーンの record は書かれる）のにイベントが流れない — broker は grant されていない subject を黙って落とす。何もエラーにならない。負系 capstone テストがまさにこの挙動を**セキュリティ**姿勢として pin しているからこそ、運用側にはこの注意書きが要る。

## Health エンドポイント

- `GET /healthz` — **liveness**、static。失敗 = 「再起動せよ」。
- `GET /readyz` — **readiness**、依存関係認識: evidence store、broker 接続（データプレーン稼働時）、外部 PDP 到達性（構成時）。失敗 = 「新しい仕事を回すな」。check エラーの詳細は server log のみで、公開 body は check ごとの pass/fail だけを返す。

スーパーバイザはこれに合わせて配線する（例: Kubernetes の `livenessProbe` → `/healthz`、`readinessProbe` → `/readyz`）。

## 永続状態

すべての永続状態は設定した data dir 以下に置かれる（`network/README.ja.md` の「状態モデル」参照）: YAML のコントロールプレーン record と、ファイルバックの evidence ディレクトリ（credential、resolution pool、audit queue、verdict）。運用上の義務は 2 つ:

- **data dir をバックアップする。** audit-reachable な deployment は、発行からはるか後の source credential 遡及解決を約束している — evidence 保持は最適化ではなく deployment の義務。
- **evidence は無制限に成長する**（retention/GC は roadmap 項目）。ディスクを監視すること。

設計上インメモリ（PoC 姿勢）: wireauth nonce store（replay 防御は restart epoch barrier で再武装）と infra-operator 状態。

## Trust material

NATS operator-mode の素材（operator/account seed、account claims JWT、broker 設定）は**帯域外で**生成し、絶対にコミットしない。quickstart の one-shot `provision` コンテナがその形を示す（re-up に対して冪等）。production では同じ成果物を自前の secret 管理で用意する。auth スタックのトークン署名素材は別物 — dev から先に変えるべきものは quickstart README の「Going to production」を参照（JWKS による非対称 provider 鍵、オペレーター管理 seed、実 service credential）。
