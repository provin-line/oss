# provin OSS
> 日本語版 — English: [README.md](README.md)

分散型データパイプラインエンジン — **dPLaaX protocol** の **`provin` wire profile**（参照実装）。すべてのデータ変換は W3C Verifiable Credential として暗号署名され、任意の参加者が独立に検証できる線形の来歴チェーンを形成する。DB 不要、YAML 駆動、セルフホスト可能。

> **Status: PoC skeleton.** ディレクトリ構造と各レイヤーの規約は整備済み。インターフェースと実装は順次追加される。

## 名前の使い分け

| 表面 | 名前 | 出現箇所 |
|---|---|---|
| プロトコル | `dplaax` | proto 名前空間（`dplaax.*.v1`）、DID メソッド（`did:dplaax`）、JSON-LD コンテキスト IRI |
| プロダクト | `provin` | このリポジトリ、CLI バイナリ（`provin`）、Docker イメージ |

PoC であることは DID の **レジストリセグメント**（例: `did:dplaax:poc.dplaax.dev:org:acme`）で表現し、メソッド名には含めない。これにより、PoC から本番への移行後も来歴チェーンが維持される。

## レイアウト

```text
api/protobuf/   プロトコル定義（buf; 名前空間 dplaax.*.v1）
gen/            生成コード（コミット済み — ビルドに buf は不要）
network/        レジストリ & コーディネーションサービス（コントロールプレーンのライブラリ + ハンドラ）
pipeline/       Pipeline プロセス ピアカタログ + 共有メカニクス
cmd/network/    ネットワークノードバイナリ（レジストリのコントロールプレーンのみ）
cmd/standalone/ オールインワンノードバイナリ（コントロールプレーン + データプレーン）—
                非推奨; cmd/network + pipeline runtime への移行が進行中
cmd/provin/     オペレーター CLI
conformance/    provin profile 適合性 vector + harness（テスト専用）
docs/           アーキテクチャ / コンセプト / プロトコル / DID
scripts/        lint 衛生チェック（`make lint` から実行）
```

上記以外のトップレベルディレクトリは **ライブラリパッケージ** — `network/`・`pipeline/`・`cmd/` が利用する純粋なドメインライブラリ群（→ [ライブラリパッケージ](#ライブラリパッケージ)）。

## 依存の方向（厳密、一方向）

```text
cmd/  network/  pipeline/          (コンシューマー)
        │
        ▼
ライブラリパッケージ                (純粋なドメイン層; proto も内部依存もなし)
        ▲
        │
      gen/  ◄── api/protobuf       (ワイヤー型; network/pipeline/cmd のみが利用)
```

ライブラリパッケージは `gen/` をインポートしない。`network/` と `pipeline/` は互いをインポートしない — 両者の通信はワイヤー（ConnectRPC / NATS）経由のみ。

## ライブラリパッケージ

- **内部依存なし**: ライブラリパッケージは `gen/`・`network/`・`pipeline/`・`cmd/` をインポートしない。Proto で生成された型はここには登場しない。
- **一方向消費**: コンシューマがライブラリパッケージに依存する。逆方向の依存は存在しない。
- ここで定義するインターフェースはシステムの安定したコントラクトである。この層の exported な識別子をリネームまたは形状変更することは、すべてのコンシューマに対する破壊的変更となる。

| パッケージ | 責務 |
|---|---|
| `did/` | DID ドメイン: W3C 文書モデル・method dispatch（`MethodOf`）。`did:dplaax` method（T1）は `did/dplaax` |
| `canon/` | 署名スコープの正規化: JCS (RFC 8785)・URDNA2015・厳格な JSON デコード |
| `vc/` | W3C VC Data Integrity: クレデンシャルモデル・ビルダー・検証器・暗号スイート・confidence 軸 |
| `crypto/` | 鍵生成・署名・検証インターフェース + Ed25519 実装 |
| `delegation/` | Pipeline/Process DID 向けのオーナー署名付き委任クレデンシャル |
| `resolver/` | DID Document 解決インターフェース + ローカル・grpc・マルチ実装 |
| `keystore/` | 秘密鍵ストレージコントラクト（KMS モデル境界） |
| `tlog/` | 組織ごとの transparency log: append-only・改竄検出可能なレコード列（監査基盤） |
| `hoconconfig/` | 3 層 HOCON 設定ローダー |
| `orgverify/` | DNS ベースの組織アイデンティティ検証 |

ライブラリ層内部の依存 DAG:

```text
vc ──► did, canon, crypto
delegation ──► vc, did, crypto
resolver ──► did
orgverify ──► did, resolver
keystore ──► crypto
tlog ──► crypto
```

## Pipeline プロセスモデル

パイプラインは、4 種類の **ピア** プロセス型のグラフ合成で構成される。いずれも特権を持たない。

| 型 | 定義的な性質 |
|---|---|
| Chained Process | ステートレスな 1:1 変換; VC チェーンを維持する |
| Source Process | 新しい FirstDrop VC を発行する（チェーンの起点） |
| Sink Process | チェーンを終端させ、外部世界へ書き出す |
| Custom Process | 少なくとも一方の I/O 側で Pipeline Contract に準拠する |

詳細は [pipeline/README.md](pipeline/README.md) を参照。拡張アダプターは **別リポジトリ** に置かれ、[pipeline/contract](pipeline/contract/) を実装する。

## 安定性とバージョニング

このリポジトリは `0.x`（[SemVer](https://semver.org/spec/v2.0.0.html)）。リリースは
[CHANGELOG.md](CHANGELOG.md) を参照。2 つの面で安定性の約束が異なる:

- **v0 credential wire は凍結済み** — credential の署名に参加するすべての
  バイト: credential の `@context` セット（embed 済み・digest pin）、Data
  Integrity proof アルゴリズム、両暗号スイート（`eddsa-jcs-2022` が default、
  `eddsa-rdfc-2022` は opt-in）とその正規化、source-commitment の計算形。
  これらの変更は発行済み credential との proof 互換性を壊すため**次 MAJOR**の
  変更となる。凍結はプロセスでなくテスト（公式 W3C vc-di-eddsa vector・KAT・
  context sha256 pin）が強制する — 正確なスコープ（本宣言が意図的にカバー
  **しない**署名面: tlog checkpoint・wire-auth・lifecycle hash）は CHANGELOG の
  凍結宣言を参照。
- **exported Go API と設定キー**は `0.x` の minor リリース間で変わりうる。
  最初に凍結される API 面は、機能セットの完成と実デプロイでの soak を経た
  `1.0` で宣言する。

## ライセンス

Apache License 2.0 — [LICENSE](LICENSE) を参照。
