# docs/
> 日本語版 — English: [README.md](README.md)

| ディレクトリ | 内容 |
|---|---|
| `architecture/` | [システム概要](architecture/overview.ja.md)、[プロセスピアカタログ](architecture/processes.ja.md)、[デプロイモデル](architecture/deployment.ja.md) |
| `concepts/` | [監査義務](concepts/audit-obligations.ja.md)。来歴モデル・パイプライン処理・スキーマルールは *planned*（信頼レイヤーの導入は当面 [overview](architecture/overview.ja.md) が担う） |
| `protocol/` | [サービス API 面](protocol/services.ja.md)（endpoint 導出含む）、[認証仕様 L1/L2](protocol/auth.ja.md) |
| `did/` | [`did:dplaax` メソッド仕様](did/method.ja.md) |

[GLOSSARY.ja.md](GLOSSARY.ja.md) が用語の語彙を定義する。定義は責務ベースで、実装値は決して持たない — 具体的なカタログや定数は package の契約と dPLaaX spec に置く。

ドキュメントは設計の意図を示す。コードとドキュメントが乖離した場合は、乖離を生じさせた同一 PR で一方を修正すること — 前身プロジェクトではアーキテクチャドキュメントの陳腐化が繰り返し問題となった。
