# vc — Verifiable Credentials（W3C Data Integrity）
> 日本語版 — English: [README.md](README.md)

`PipelinePassCredential`（パイプラインのすべてのプロセス境界で発行される VC）のクレデンシャルモデル・証明の作成と検証・暗号スイートレジストリ・confidence 評価（3 軸）と、型を問わないクレデンシャルの Signer authenticity の軸だけの評価。

## コア設計: ボディを真実の単一ソースとする

クレデンシャル構造体はデータフィールドを一切公開しない。正規ボディマップが署名とハッシュ両方の唯一の真実ソースであり、読み取りはデフェンシブコピーを返すアクセサ経由で行う。構築パスはちょうど 3 つ: 署名付きビルド・署名なしビルド（テスト/リレー）・JSON アンマーシャル（検証器パス）。未知の署名スコープフィールドはラウンドトリップ後も保持されるため、将来の語彙追加はコード変更なしにハッシュに参加できる。

（根拠: 前バージョンのコードベースでは、構造体フィールドの変更が署名ボディからサイレントに乖離するという dual-source バグが発生していた。）

## 証明アルゴリズム

```
hashData = SHA-256(canon(proofConfig)) ‖ SHA-256(canon(document))
proofValue = base58btc("z" multibase) Ed25519 signature over hashData
```

暗号スイート: `eddsa-jcs-2022`（Phase 1、MUST）・`eddsa-rdfc-2022`（Phase 2、MAY）。`eddsa-jcs-2022` は init で登録し、発行の既定。`eddsa-rdfc-2022` は、process が `vc.RegisterEdDSARDFC2022` を、`main` か、main package の `init` 関数から 1 度呼んだ時だけ登録する。確かめると、信用できない文書に、署名を確かめる前に JSON-LD の処理が走るので、それを負うのは verifier が選んだ時だけにする（手間の上限と、断る文書の形は、関数の doc に書いてある）。呼ぶまでは、どの関数もどの `Verifier` も、この suite の proof を断る。関数は `vc.ErrCryptosuiteNotRegistered` を包み、`vc.RegisterEdDSARDFC2022` の名前を出した誤りを返し、`Verifier` は issuer を引く前に、署名者の真正性を failed とする。呼んだ後は、発行者が `CreateProof` か `WithCryptosuite` にこの suite を渡した時に使う。この module の package はどれも呼ばない（`scripts/check-rdfc-registration.sh`）。その canonicalizer は、登録の時に **IRI 展開プローブ**をパスしなければならない — 壊れた正規化を提供するより process がパニックする。

## チェーントポロジー — 線形不変

- `previousCredential` は**単数**: チェーンは厳密に線形であり、DAG にはならない。欠落または null はチェーン起点（FirstDrop）を意味する: 外部インジェストまたは集約。
- 集約が新しいチェーンを開始する判定基準はトリガー規則（単一の適合イベントに起こされた実行ではないこと）であり、集約結果がどの単一入力とも同一性関係を持たないことはその根拠（Paper 01 §4.8）。**ベースのクレデンシャルスキーマは上流参照フィールドを持たない** — 入力マニフェストはデータペイロード / ビジネスロジックの関心事。唯一公認された拡張が**ソースコミットメント**（`derived_from` / `source_root` / `source_root_canonical`）: **audit-reachable conformance class** の下で任意のクレデンシャルが運ぶ監査属性であり（`previousCredential` と直交 — chain-preserving は先行イベントを含む全消費分に commit する）、open な署名ボディに dplaax JSON-LD context で宣言される profile 語彙として載る（wire 名は dPLaaX spec が確定済み — profile 横断で共有されるため profile ごとに改名しない）。これは消費した source 集合への content commitment であって親リンクではない — チェーントポロジーは厳密に線形のままで、Paper 01 §4.8 の排除（チェーンに上流リンクなし・ベーススキーマに上流フィールドなし）は維持される。
- subject はハッシュのみを運び、ペイロード自体は運ばない（Paper 01 §4.3）: データを埋め込まずに完全性を証明する。

## 信頼評価

- 各軸と全体は 3 状態ドメイン: `failed ⊏ indeterminate ⊏ verified`、最大下界（最弱リンク）で合成。`failed` = 矛盾が確定、`indeterminate` = 現在の入力では完了不能（後で解決し得る）。この区別が、同じスナップショットを与えられた任意の検証器が同じ結果を出す決定論性を支える。
- 軸: **Data integrity**（入出力バインディング + スキーマ content-hash）、**Signer authenticity**（署名 + `proof.created` 時点の暗号スイートライフサイクル）、**Chain consistency**（終端 Owner DID までの controller 連鎖 + 順序整合）。
- 発行者の確かめ方は差し替えられる: `IssuerVerifier` が、proof を確かめる鍵と、発行者に責任を負う Owner を返す（`WithIssuerVerifier`。既定の `NewDIDDocumentIssuers` は DID の文書を読む）。proof の形の検査、proof そのものの検証、「Owner は発行者の Process DID が名指すもの」は Verifier が持つ。
- 型を問わない Signer authenticity: `Verifier.VerifySignerAuthenticity` は、`Credential`（Data Integrity の proof つきの、どの型の VC の wire 形でもよい。型の規則は持たない）について、Signer authenticity の軸だけを、`Verify` と同じ実装で判定する。確かめるのは、報告する suite contract の正規化でこの本文と同じになる文書に、誰が署名したかだけである。型・欄・有効期間・発行者のどの鍵で署名してよいかは、呼ぶ側が自分の型の規則で確かめる（正規化で区別されない値は、メソッドの説明を参照）。
- チェーン分類（confidence と直交）: `ChainOrigin` / `ChainSingleOwnerDerived` / `ChainMultiOwnerDerived` — 誰が署名し、いくつの信頼境界を跨いだか。データがどう作られたかではない。
- ライフサイクルフェーズ: Unknown → Active → Deprecated → Sunset、`proof.created` をキーに評価。**ゼロ値はフェイルクローズ。** ライフサイクルポリシーの公開形（append-only な registry artifact かサービスか）は仕様層で確定待ち。
- no-op 識別子の禁止（`""`・`"none"`・`"null"`・`"identity"`）は登録時と検証時の両方で適用（JOSE `alg:none` クラス防御）。
- 署名を見ない結び付きだけの検査: `ValidateChainLinks` はクレデンシャルの間の結び付き（と、起点が前を持たないこと）を確かめ、`ValidateChainFrom` は加えて起点の `inputHash` を与えた入力に結び付ける。`VerifyChain` と同じ結び付きの検査を使う。結び付いた連鎖の前の部分も結び付いているので、末尾が欠けたことは分からない。
- ソースコミットメント検証（`VerifySourceCommitment`）は意図的に **3 規範軸の外**・イベント毎経路の外に置く: オンデマンドの監査操作である。source クレデンシャルは非同期に収集し（VC リゾルバー・取引相手のストア）、claim された集合が揃うまで verdict は `indeterminate` — ホットパスは境界あたり O(1) のまま。コミットメントが証明するのは claim の完全性ではなく**改竄不能性**（発行後の tamper-evidence）— 申告漏れの検出はイングレス VC ストアとの突合という監査層の作業。

## contexts/

コンパイル時に埋め込まれた JSON-LD コンテキストドキュメント（`go:embed`）: W3C credentials v2・dplaax VC v1・security data-integrity v2。実行時にはフェッチしない — 検証器の出力は上流 URL が何を返すかに関わらず安定でなければならない。
