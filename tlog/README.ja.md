# tlog — 組織ごとの Transparency Log
> 日本語版 — English: [README.md](README.md)

Append-only・改竄検出可能・独立検証可能なレコード列 — 監査モデルの永続化基盤。ネットワーク全体のログは存在しない（per-peer trust root）: 各組織が自身の DID の下で自身のログをホストする。

## なぜこれが要なのか

事後監査モデルは「当事者が編集も否認もできない記録」の突合で責任を帰属させる: emission stream・ingress 受領記録・購読登録・VC body。そのすべてが「記録がまだ存在し、こっそり書き換えられていない」ことを前提とする。本パッケージはその保証の契約である。

## 契約設計: 契約は実運用級、実装は段階的

契約には CT 級ログに必要なもの — 署名付き checkpoint（否認不能な log head）と、inclusion / consistency proof のための optional な `Prover` capability — を最初から含める。実装は**契約を変えずに**段階的に強化する:

| 段階 | 実装 | 改竄検出 | Proof |
|---|---|---|---|
| PoC | 永続 hash-chain ファイルログ | chain hash（検証は replay） | なし（`Prover` 未実装） |
| 実運用 | Merkle tree ログ（CT 級） | 署名付き tree head | `Prover` 経由の inclusion + consistency |

呼び出し側は型アサーションで proof 対応を発見する。未対応なら監査側は chain replay で代替する。

## 消費者

- publisher の emission log（envelope hash + sequence number）— 監査突合の「配送実績」
- ingress 受領記録（検証済み ingress クレデンシャル）
- 永続 VC ストアの登録ログ
- 暗号スイート lifecycle registry（`vc.LifecycleRegistry`）— wire profile が公開する append-only な `(id, phase, effective_date)` artifact

## 規約

- レコードの変更・削除は決して行わない。監査期間にわたる保持は deployment 義務。
- checkpoint 署名は `crypto` 経由で組織の鍵を使う（注入）。ログは鍵素材を保持しない。
