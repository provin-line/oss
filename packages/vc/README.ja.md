# packages/vc — Verifiable Credentials（W3C Data Integrity）
> 日本語版 — English: [README.md](README.md)

`PipelinePassCredential`（パイプラインのすべてのプロセス境界で発行される VC）のクレデンシャルモデル・証明の作成と検証・暗号スイートレジストリ・トラストポリシー。

## コア設計: ボディを真実の単一ソースとする

クレデンシャル構造体はデータフィールドを一切公開しない。正規ボディマップが署名とハッシュ両方の唯一の真実ソースであり、読み取りはデフェンシブコピーを返すアクセサ経由で行う。構築パスはちょうど 3 つ: 署名付きビルド・署名なしビルド（テスト/リレー）・JSON アンマーシャル（検証器パス）。未知の署名スコープフィールドはラウンドトリップ後も保持されるため、将来の語彙追加はコード変更なしにハッシュに参加できる。

（根拠: 前バージョンのコードベースでは、構造体フィールドの変更が署名ボディからサイレントに乖離するという dual-source バグが発生していた。）

## 証明アルゴリズム

```
hashData = SHA-256(canon(proofConfig)) ‖ SHA-256(canon(document))
proofValue = base58btc("z" multibase) Ed25519 signature over hashData
```

暗号スイート: `eddsa-jcs-2022`（Phase 1、MUST）・`eddsa-rdfc-2022`（Phase 2、MAY）。新しいスイートはディスパッチテーブルに登録し、**初期化時の IRI 展開プローブ**をパスしなければならない — 壊れた正規化を提供するよりバイナリ起動時にパニックする。

## チェーン・オリジンフィールド

- `previousCredential` — 前のVCへのハッシュリンク（空 = FirstDrop）。
- `derived_from` / `source_root` / `source_root_canonical` — Origin Source の来歴（ソース VC ワイヤーバイトに対する Merkle コミットメント）。ビルダーと検証器の両方に最初から組み込まれている（前バージョンではこれらが仕様のみにとどまっていた — その乖離がこの PoC が最初に解消するものである）。

## トラストポリシー

- 検証信頼度 = 各軸（署名・DID 解決・スキーマ）の最弱リンク。
- アローリスト: 2 層構造（パイプラインごとのオーバーライドがレジストリのアドバイザリより優先）。`nil` = 継承 と 空 = 全拒否 の区別は重要な意味を持つ。
- ライフサイクルフェーズ: Unknown → Active → Deprecated（告知日猶予期間あり）→ Sunset。**ゼロ値はフェイルクローズ。**
- no-op 識別子の禁止（`""`・`"none"`・`"null"`・`"identity"`）はアローリスト構築時と検証時の両方で適用される（JOSE `alg:none` クラス防御）。

## contexts/

コンパイル時に埋め込まれた JSON-LD コンテキストドキュメント（`go:embed`）: W3C credentials v2・dplaax VC v1・security data-integrity v2。実行時にはフェッチしない — 検証器の出力は上流 URL が何を返すかに関わらず安定でなければならない。
