# provin OSS
> 日本語版 — English: [README.md](README.md)

分散型データパイプラインエンジン — **dPLaaX protocol** の **`provin` wire profile**（参照実装）。すべてのデータ変換は W3C Verifiable Credential として暗号署名され、任意の参加者が独立に検証できる線形の来歴チェーンを形成する。DB 不要、YAML 駆動、セルフホスト可能。

> **Status: PoC skeleton.** ディレクトリ構造と各レイヤーの規約は整備済み。インターフェースと実装は順次追加される。

## 名前の使い分け

| 表面 | 名前 | 出現箇所 |
|---|---|---|
| プロトコル | `dplaax` | proto 名前空間（`dplaax.*.v1`）、DID メソッド（`did:dplaax`）、JSON-LD コンテキスト IRI |
| プロダクト | `provin` | このリポジトリ、CLI バイナリ（`provin`）、Docker イメージ |

PoC であることは DID の **レジストリセグメント**（例: `did:dplaax:poc.dplaax.io:org:acme`）で表現し、メソッド名には含めない。これにより、PoC から本番への移行後も来歴チェーンが維持される。

## レイアウト

```text
api/protobuf/   プロトコル定義（buf; 名前空間 dplaax.*.v1）
gen/            生成コード（コミット済み — ビルドに buf は不要）
network/        レジストリ & コーディネーションサーバー（単一バイナリ）
pipeline/       Pipeline Component ピアカタログ + 共有メカニクス
cmd/provin/     オペレーター CLI
docs/           アーキテクチャ / コンセプト / プロトコル / DID
scripts/        CI 衛生チェック
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
| `did/` | `did:dplaax` メソッド: パース・DID Document モデル・バリデーション・公開鍵抽出 |
| `canon/` | 署名スコープの正規化: JCS (RFC 8785)・URDNA2015・厳格な JSON デコード |
| `vc/` | W3C VC Data Integrity: クレデンシャルモデル・ビルダー・検証器・暗号スイート・トラストポリシー |
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

## Pipeline Component モデル

パイプラインは、4 種類の **ピア** コンポーネント型のグラフ合成で構成される。いずれも特権を持たない。

| 型 | 定義的な性質 |
|---|---|
| FilterConvert | ステートレスな 1:1 変換; VC チェーンを維持する |
| Origin Source | 新しい FirstDrop VC を発行する（チェーンの起点） |
| External Sink | チェーンを終端させ、外部世界へ書き出す |
| Custom | 少なくとも一方の I/O 側で Pipeline Contract に準拠する |

詳細は [pipeline/README.md](pipeline/README.md) を参照。拡張アダプターは **別リポジトリ** に置かれ、[pipeline/contract](pipeline/contract/) を実装する。

## ライセンス

Apache License 2.0 — [LICENSE](LICENSE) を参照。
