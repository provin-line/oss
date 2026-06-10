# provin OSS
> 日本語版 — English: [README.md](README.md)

**dplaax protocol** を実装した分散型データパイプラインエンジン。すべてのデータ変換は W3C Verifiable Credential として暗号署名され、任意の参加者が独立に検証できる来歴チェーンを形成する。DB 不要、YAML 駆動、セルフホスト可能。

> **Status: PoC skeleton.** ディレクトリ構造と各レイヤーの規約は整備済み。インターフェースと実装は順次追加される。

## 名前の使い分け

| 表面 | 名前 | 出現箇所 |
|---|---|---|
| プロトコル | `dplaax` | proto 名前空間（`dplaax.*.v1`）、DID メソッド（`did:dplaax`）、JSON-LD コンテキスト IRI |
| プロダクト | `provin` | このリポジトリ、CLI バイナリ（`provin`）、Docker イメージ |

PoC であることは DID の **レジストリセグメント**（例: `did:dplaax:poc.dplaax.io:org:acme`）で表現し、メソッド名には含めない。これにより、PoC から本番への移行後も来歴チェーンが維持される。

## レイアウト

```
api/protobuf/   プロトコル定義（buf; 名前空間 dplaax.*.v1）
gen/            生成コード（コミット済み — ビルドに buf は不要）
packages/       共有ライブラリ（純粋なドメイン層; このリポジトリ内の他モジュールに依存しない）
network/        レジストリ & コーディネーションサーバー（単一バイナリ）
pipeline/       Pipeline Component ピアカタログ + 共有メカニクス
cmd/provin/     オペレーター CLI
docs/           アーキテクチャ / コンセプト / プロトコル / DID
scripts/        CI 衛生チェック
```

## 依存の方向（厳密、一方向）

```
cmd/  network/  pipeline/          (コンシューマー)
        │
        ▼
    packages/                      (純粋なドメイン層; proto も内部依存もなし)
        ▲
        │
      gen/  ◄── api/protobuf       (ワイヤー型; network/pipeline/cmd のみが利用)
```

`packages/` は `gen/` をインポートしない。`network/` と `pipeline/` は互いをインポートしない — 両者の通信はワイヤー（ConnectRPC / NATS）経由のみ。

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
