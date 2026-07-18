# デプロイメント
> 日本語版 — English: [deployment.md](deployment.md)

provin ノードのデプロイ形態と、**load-bearing な**（間違えるとノードは正常に起動するのに仕事ができない）少数の設定判断について。設定キーの正典は各 package の `reference.conf` — 本ページはそれらが局所的にしか説明できない横断的な判断を扱う。ノードが*何であるか*（平面・信頼層）は [overview.ja.md](overview.ja.md)、ループが何かは [processes.ja.md](processes.ja.md) を参照。

## デプロイ形態

| 形態 | 構成 | 参照 |
| --- | --- | --- |
| 単一ホスト評価 | Docker Compose で全部を 1 ホストに: node + 実 auth スタック（auth.provider、policy-verifier）+ NATS、trust material は provision | [`deploy/quickstart/`](../../deploy/quickstart/README.md) |
| 単一組織 production | レジストリごとに 1 つの `standalone` ノード、外部 PDP、オペレーター管理の NATS trust material | 本ページ |
| 組織間フェデレーション | 組織ごとに 1 ノード。NATS account 境界が export/import seam を運び、peer 間は ChainPeerService（L2 wireauth） | [`network/README.ja.md`](../../network/README.ja.md) |

`cmd/standalone` はノードを単一バイナリとして構成する: HTTP コントロールプレーン（ConnectRPC サービス + 公開 DID 解決 + health エンドポイント）とデータプレーン（pipeline loop）が 1 プロセス・1 つの signal-cancelled context で動く。

現在バイナリは 2 つ存在する。`cmd/standalone` は上記の all-in-one 構成のまま利用でき続けるが、**非推奨**。`cmd/network` は同じコントロールプレーンのみを動かす — データプレーンは無く、設定に pipeline loop が 1 つでも宣言されていれば起動を拒否する。`cmd/network` と組む pipeline runtime は今後の作業で、それが実装されるまで `cmd/standalone` が pipeline loop を動かす唯一の手段。

evidence の書き込みは通常の wire RPC として実装されている（`AuditService.RegisterEvidence`、`PayloadStoreService.RetainPayload`、`ChainService.ReportEmitHealth`）。したがって将来の pipeline runtime は、他の client と同じ経路でこれらに到達でき、control-plane バイナリへの in-process ブリッジは不要である。relationship-evidence log（`tlog`）とアーカイバル sink の reject log は、それぞれの design gate を待つ間 in-process のまま残る。

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

- **ノードは更新済み claims を自動で push する**（sys-user 資格情報 — `sys-user-jwt-file` / `sys-user-seed-file` — を設定した場合）: grant の発行処理の一部として稼働中 broker に push（`$SYS.REQ.ACCOUNT.<account>.CLAIMS.UPDATE`）し、push が確認できなければ grant RPC は loud に失敗する。quickstart はこれを標準で配備し、sys user はこの node account の claims-update subject だけに narrow 済み。それでも sys-user ファイルは trust 資材 — production では署名鍵と同格に保護する。
- **fallback runbook**（sys user 未設定・障害復旧時）: 手動で claims を push（`nsc push`、または全 resolver 種別が応答する per-account subject `$SYS.REQ.ACCOUNT.<account>.CLAIMS.UPDATE` への request）するか、broker を再起動して再読込させる。
- broker はノードが JWT を publish するのと**同じディレクトリ**から account を解決すべき（quickstart は nats directory resolver をその上で走らせる）。conf に bake した `resolver_preload` 付き memory resolver は、grant が載った瞬間に stale 化し、broker 再起動で旧 claims を復活させる — static な単一 account 構成以外でこの形はデプロイしないこと。
- そのディレクトリの JWT ファイルは双方が in-place で書き換える（node の publisher は grant 時、broker の resolver は claims-update 保存時）。**broker と node は同一 uid で走らせる必要がある**（quickstart はそうしている）。publisher は書き込みごとにファイルモードを締め直すため、uid を分けた構成では相互書き込み可能な状態を今は維持できない。

push が無い時の症状: `chain subscribe` は成功する（コントロールプレーンの record は書かれる）のにイベントが流れない — broker は grant されていない subject を黙って落とす。何もエラーにならない。負系 capstone テストがまさにこの挙動を**セキュリティ**姿勢として pin しているからこそ、運用側にはこの注意書きが要る。

## Health エンドポイント

- `GET /healthz` — **liveness**、static。失敗 = 「再起動せよ」。
- `GET /readyz` — **readiness**、依存関係認識: evidence store、broker 接続（データプレーン稼働時）、外部 PDP 到達性（構成時）。失敗 = 「新しい仕事を回すな」。check エラーの詳細は server log のみで、公開 body は check ごとの pass/fail だけを返す。

スーパーバイザはこれに合わせて配線する（例: Kubernetes の `livenessProbe` → `/healthz`、`readinessProbe` → `/readyz`）。

## TLS 終端

ノードは平文 **h2c**（HTTP/2 cleartext）を提供する。L1 RPC は bearer token を平文で運ぶので、非 loopback な平文 listener は on-path 攻撃者に捕捉・replay される。そのため default `listen-addr` は **loopback 限定**（`127.0.0.1:8443`、secure by default）で、listener を loopback から外す際に transport posture を選ばないと boot guard が **fail-closed** する。いずれかを選ぶ:

**(a) ノード自前 TLS。** `provin.network.core.tls.cert-file` と `key-file` を設定（両方 or どちらも無し）。ノードが HTTP/2 over TLS（ALPN）を提供する。留意:

- **protocol floor は TLS 1.2**（library default 任せではなく明示 pin）。**cipher suite は Go 標準ライブラリの secure default に依存**する — これは意図的な選択で、TLS 1.3 の cipher は Go の API から選べず、allowlist を固定すると将来の stdlib 側のセキュリティ改善を塞ぐため。
- 証明書 pair は **boot preflight** で検証する — store 生成や transport 接続より前なので、読めない・不正・不一致の pair は副作用のない clean な boot 失敗になる。serve に使うのは preflight で load した pair 自体で、以後ファイルを **再読込しない**。したがってファイル差し替えでは hot reload されず、**rotation は restart が必要**。
- DID resolution は `https://{registry}` の **443** を期待する一方、listener の default は `:8443`。443 でマッピング/提供するか resolver base（`resolver-base-url` / `registry-base-urls`）を override して、relying party が TLS endpoint に到達できるようにする。
- advertised service endpoint（`#vc-resolver`、`#audit`）・VC-store/upstream URL・auth-provider registry URL は、TLS endpoint に到達する箇所では `https://` にする。
- 証明書の **SAN は client が使う hostname を覆う**こと。private CA は各 client / container の trust store に導入する。
- `/healthz`・`/readyz`・`/metrics` も HTTPS に移る — probe/scraper を更新する。

**(b) 前段の TLS terminator。** reverse proxy / LB で TLS を終端し、`provin.network.core.tls.allow-cleartext = true` で平文 listener を承認する。これは**承認であって強制ではない**: 平文 backend が **terminator からのみ到達可能**になるようにする責務が運用側にある（shared netns での loopback bind、private network、firewall / security group）。guard はこの隔離を検証できない。

## Metrics

`GET /metrics` は OpenTelemetry counter を Prometheus exposition 形式で返す。`provin.network.core.metrics.enabled` でゲート（**default `false`**: このエンドポイントは serving listener 上で無認証であり、loop 名・流量・失敗率・判定率を露出する — `/healthz` より情報量が多い。listener のネットワークが信頼できる場所でのみ有効化する。quickstart compose は有効化済み）。

安定 metric family（operational contract — credential wire 凍結の対象外だが、リネームは CHANGELOG 記載対象）:

| Prometheus 名 | 属性 | 意味 |
| --- | --- | --- |
| `provin_pipeline_emit_attempts_total` | `loop`, `outcome=success\|failure` | producing loop ごとの Emit 結果。Emit の戻り値がキー（success = primary form 配送済み。stripped publish の失敗はここでは success のまま） |
| `provin_pipeline_emit_stripped_failures_total` | `loop` | dual-emit する loop ごとの stripped publish 失敗数 |
| `provin_pipeline_verify_results_total` | `loop`, `outcome=verified\|failed\|indeterminate\|error` | consuming loop ごとの per-credential **verifier API** 結果 — loop の accept/reject ポリシーの下にある seam（`error` = verifier が非 context エラーを返した、または異常な nil 結果） |
| `provin_audit_verdicts_total` | `verdict=verified\|failed\|indeterminate` | durable に記録された audit verdict の **write** 数（linear-chain overall verdict 別。head 数ではなく write 数: 再 audit・hole の毎 tick 再記録・abandon 確定はそれぞれ数える） |

family の存在は capability に従う: family（とその固定・ゼロ初期化のラベル集合）は node がその capability を構成しているときにのみ現れる — emit 系列は producing loop のみ、stripped 系列は dual-emit 構成（payload store 配線済み）のみ、verify 系列は consuming loop のみ、audit verdicts は audit runner 稼働時のみ。

## 永続状態

すべての永続状態は設定した data dir 以下に置かれる（`network/README.ja.md` の「状態モデル」参照）: YAML のコントロールプレーン record と、ファイルバックの evidence ディレクトリ（credential、resolution pool、audit queue、verdict）。運用上の義務は 2 つ:

- **data dir をバックアップする。** audit-reachable な deployment は、発行からはるか後の source credential 遡及解決を約束している — evidence 保持は最適化ではなく deployment の義務。
- **evidence は default で無制限に成長する**。ディスクを監視すること。record を削除せず live ディスクを抑えるには、relationship-evidence log を cold archive へ rotation する（下記）。1 つの body は複数の credential variant（同じ主張に対する別の署名形）を蓄積し得る。variant set が append-only なのは設計であって漏れではない — 後着の不正 proof が先着の正当な proof を追い出せないのは、何も evict しないからこそ成立する。admission は L1 gate 越しで、quota と quarantine は external-effect gate と共に入る。

credential store は各 body の variant を `<evidence-dir>/credentials/variants/<bodyhex>/<varianthex>.json` に置く。従来から書いていた `<bodyhex>.json` はそのままの位置に残り、body-only projection として維持される — したがって**このディレクトリに対して旧 binary へ rollback しても全 body が解決でき**、subtree は旧 binary から見えない。

設計上インメモリ（PoC 姿勢）: wireauth nonce store（replay 防御は restart epoch barrier で再武装）と infra-operator 状態。

### evidence log の rotation

relationship-evidence log は append-only かつ tamper-evident（open 時に replay 検証される hash chain）: record は**決して**削除・改変しない — 保持がそのまま audit horizon である。live ディスクを抑えるには、record を削除するのではなく古い record を cold archive へ rotation する:

```console
# 先に daemon を停止する — log は single-opener lock を取るので、
# online の rotate は loud に失敗する（稼働中の log を壊すことはない）。
$ provin evidence rotate --dir <data-dir>/relationship-evidence
```

rotation は現在の log を `archive/seg-NNNNNN/` へ copy し（`manifest.json` に size・chain head・そして checkpoint signer が武装していれば署名済み最終 checkpoint を記録）、live log を fresh な空 genesis へ truncate する。archive された segment は独立に replay 検証可能。必要に応じて `archive/` を安価な cold storage へ移し、audit horizon の間保持する。rotation は crash-safe: 中断された rotate は次回 daemon 起動時に完了またはロールバックされる。

**segment stitching（rotation をまたぐ audit）。** rotation 後、live log の record index は 0 から振り直されるため、完全な履歴は *segment 番号 → index* の順で並ぶ: `seg-000001` の record `0..N₁-1`、次に `seg-000002`、…、最後に live log。各 segment は自身の genesis から独立に検証できる。完全な relationship 履歴を再構成する監査者は、archive segment を `seg-NNNNNN` 昇順に読み、最後に live log を読む。rotation をまたいで evidence を永続 global index で参照する consumer は `(segment, index)` へ切り替える必要がある。現在の relationship-evidence 経路はそうしていない（live log に append し audit する）ので、rotation は透過的。

unsigned の注意: evidence log が checkpoint signer で武装されていない限り、archive segment の完全性は chain replay + filesystem のアクセス制御に依存する — live の unsigned log と同じ信頼モデル。`manifest.json` の head は storage summary であって暗号学的 seal ではない。

## Trust material

NATS operator-mode の素材（operator/account seed、account claims JWT、broker 設定）は**帯域外で**生成し、絶対にコミットしない。quickstart の one-shot `provision` コンテナがその形を示す（re-up に対して冪等）。production では同じ成果物を自前の secret 管理で用意する。auth スタックのトークン署名素材は別物 — dev から先に変えるべきものは quickstart README の「Going to production」を参照（JWKS による非対称 provider 鍵、オペレーター管理 seed、実 service credential）。
