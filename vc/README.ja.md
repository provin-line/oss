# vc — Verifiable Credentials（W3C Data Integrity）
> 日本語版 — English: [README.md](README.md)

`PipelinePassCredential`（パイプラインのすべてのプロセス境界で発行される VC）のクレデンシャルモデル・証明の作成と検証・暗号スイートレジストリ・confidence 評価（3 軸）。

## コア設計: ボディを真実の単一ソースとする

クレデンシャル構造体はデータフィールドを一切公開しない。正規ボディマップが署名とハッシュ両方の唯一の真実ソースであり、読み取りはデフェンシブコピーを返すアクセサ経由で行う。構築パスはちょうど 3 つ: 署名付きビルド・署名なしビルド（テスト/リレー）・JSON アンマーシャル（検証器パス）。未知の署名スコープフィールドはラウンドトリップ後も保持されるため、将来の語彙追加はコード変更なしにハッシュに参加できる。

（根拠: 前バージョンのコードベースでは、構造体フィールドの変更が署名ボディからサイレントに乖離するという dual-source バグが発生していた。）

## 証明アルゴリズム

```
hashData = SHA-256(canon(proofConfig)) ‖ SHA-256(canon(document))
proofValue = base58btc("z" multibase) Ed25519 signature over hashData
```

暗号スイート: `eddsa-jcs-2022`（Phase 1、MUST）・`eddsa-rdfc-2022`（Phase 2、MAY）。新しいスイートはディスパッチテーブルに登録し、**初期化時の IRI 展開プローブ**をパスしなければならない — 壊れた正規化を提供するよりバイナリ起動時にパニックする。

## チェーントポロジー — 線形不変

- `previousCredential` は**単数**: チェーンは厳密に線形であり、DAG にはならない。空/欠落はチェーン起点（FirstDrop）を意味する: 外部インジェストまたは集約。
- 集約が新しいチェーンを開始する判定基準はトリガー規則（単一の適合イベントに起こされた実行ではないこと）であり、集約結果がどの単一入力とも同一性関係を持たないことはその根拠（Paper 01 §4.8）。**ベースのクレデンシャルスキーマは上流参照フィールドを持たない** — 入力マニフェストはデータペイロード / ビジネスロジックの関心事。唯一公認された拡張が**ソースコミットメント**（`derived_from` / `source_root` / `source_root_canonical`）: **audit-reachable conformance class** の下で任意のクレデンシャルが運ぶ監査属性であり（`previousCredential` と直交 — chain-preserving は先行イベントを含む全消費分に commit する）、open な署名ボディに dplaax JSON-LD context で宣言される profile 語彙として載る（wire 名は dPLaaX spec が確定済み — profile 横断で共有されるため profile ごとに改名しない）。これは消費した source 集合への content commitment であって親リンクではない — チェーントポロジーは厳密に線形のままで、Paper 01 §4.8 の排除（チェーンに上流リンクなし・ベーススキーマに上流フィールドなし）は維持される。
- subject はハッシュのみを運び、ペイロード自体は運ばない（Paper 01 §4.3）: データを埋め込まずに完全性を証明する。

## 信頼評価

- 各軸と全体は 3 状態ドメイン: `failed ⊏ indeterminate ⊏ verified`、最大下界（最弱リンク）で合成。`failed` = 矛盾が確定、`indeterminate` = 現在の入力では完了不能（後で解決し得る）。この区別が、同じスナップショットを与えられた任意の検証器が同じ結果を出す決定論性を支える。
- 軸: **Data integrity**（入出力バインディング + スキーマ content-hash）、**Signer authenticity**（署名 + `proof.created` 時点の暗号スイートライフサイクル）、**Chain consistency**（終端 Owner DID までの controller 連鎖 + 順序整合）。
- チェーン分類（confidence と直交）: `ChainOrigin` / `ChainSingleOwnerDerived` / `ChainMultiOwnerDerived` — 誰が署名し、いくつの信頼境界を跨いだか。データがどう作られたかではない。
- ライフサイクルフェーズ: Unknown → Active → Deprecated → Sunset、`proof.created` をキーに評価。**ゼロ値はフェイルクローズ。** ライフサイクルポリシーの公開形（append-only な registry artifact かサービスか）は仕様層で確定待ち。
- no-op 識別子の禁止（`""`・`"none"`・`"null"`・`"identity"`）は登録時と検証時の両方で適用（JOSE `alg:none` クラス防御）。
- ソースコミットメント検証（`VerifySourceCommitment`）は意図的に **3 規範軸の外**・イベント毎経路の外に置く: オンデマンドの監査操作である。source クレデンシャルは非同期に収集し（VC リゾルバー・取引相手のストア）、claim された集合が揃うまで verdict は `indeterminate` — ホットパスは境界あたり O(1) のまま。コミットメントが証明するのは claim の完全性ではなく**改竄不能性**（発行後の tamper-evidence）— 申告漏れの検出はイングレス VC ストアとの突合という監査層の作業。

## contexts/

コンパイル時に埋め込まれた JSON-LD コンテキストドキュメント（`go:embed`）: W3C credentials v2・dplaax VC v1・security data-integrity v2。実行時にはフェッチしない — 検証器の出力は上流 URL が何を返すかに関わらず安定でなければならない。
