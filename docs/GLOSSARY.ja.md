# 用語集

> 日本語版 — English: [GLOSSARY.md](GLOSSARY.md)

定義は**責務ベース**: 各項目はその用語が*何であり*、何を保証するかだけを述べ、現状の実装値（カタログの中身、個数、アルゴリズム選択、ワイヤ上のリテラル）は書かない。具体値は package の契約と dPLaaX spec が正本であり、本ファイルはそれらと共に drift してはならない。

## プロトコルと命名

**dPLaaX** — 本リポジトリが実装するプロトコル。すべてのデータ変換を署名付きクレデンシャルとして attest し、検証可能な来歴チェーンを形成する。ワイヤ名前空間（proto パッケージ、DID メソッド、JSON-LD context）はプロトコルが所有し、実装からは独立している。

**provin** — プロダクト。本リポジトリで保守される dPLaaX の参照 *wire profile*。この名前は成果物（リポジトリ、CLI、イメージ）と profile の拡張名前空間にのみ現れ、プロトコルのワイヤ名前空間には決して現れない。

**wire profile** — dPLaaX wire spec と具体実装の間にある宣言レイヤー。profile はどのプロトコルカタログを採用するかを宣言し、プロトコルの default を狭めたり厳しくしたりでき、namespace-prefix 付きの拡張を追加できる。プロトコル規範には矛盾してはならない。

## クレデンシャルとチェーン

**PipelinePassCredential (PPC)** — パイプライン層の唯一のクレデンシャル型。1 つのプロセス境界が入力を消費し出力を生成したことを attest する Verifiable Credential。subject はコンテンツハッシュと宣言を運び、payload 自体は決して運ばない。

**来歴チェーン (provenance chain)** — `previousCredential` で連結された PPC の厳密に線形な列。各リンクの先行はちょうど 0 または 1。線形チェーンで表現できない系譜は、チェーンを分岐させるのではなく origin 境界で扱う。

**content commitment** — 成果物を名前やロケータではなく、canonical なバイト形のハッシュで参照すること。チェーンリンクが content commitment を使うのは、長期監査がレジストリの生存に依存しないようにするため。

**previousCredential** — PPC のチェーンリンクフィールド。先行クレデンシャルへの content commitment。不在はその credential が FirstDrop であることを示す。

**FirstDrop** — 先行を持たない PPC。チェーンの起点であり、このモデルの意図的な信頼境界。FirstDrop は「誰が・どのスキーマで・どのバイト列を発行したか」を attest し、取り込み以前の世界については何も主張しない。

**トリガー規則 (trigger rule)** — チェーン位相を決める規範的基準: 境界の実行が単一の準拠先行イベントの到着によってトリガーされた場合に限り chain-preserving。それ以外のトリガーはすべて FirstDrop となる。

**データフロー不変量 (data-flow invariant)** — 各クレデンシャルの出力ハッシュが後続の入力ハッシュと一致するという保証。検証者は payload を読み直さずにチェーン全体のバイトレベル連続性を証明できる。

**payload** — パイプラインを流れる実データ。ハッシュでクレデンシャルに束縛され完全性保護されるが、credential 層に埋め込まれることも、そこから復元・解釈されることもない。

**transformationType** — 境界の宣言された派生意味論: 出力が入力との間に持つと主張する関係の種類。語彙は 2 層: プロトコルが所有するベース値と、profile の名前空間を prefix した拡張。署名者による宣言であり、機械検証される性質ではない。

**SchemaRef** — 出力の登録済みスキーマへの content-commit された参照。スキーマの遡及的改変を暗号学的に検出可能にする。

**SourceCommitment** — 任意のクレデンシャルが運べる attest。境界が消費した準拠 source クレデンシャル全集合への commitment（chain-preserving ではトリガーの先行イベントも含む — 全消費分セマンティクス）。*監査属性*であって親リンクではない: チェーンは線形のままであり、外界からの読み取りは意図的にスコープ外。

**source_root** — SourceCommitment 内の Merkle set commitment。消費した source クレデンシャル群への、順序非依存でコンパクトな commitment。source ごとの inclusion proof を支える。

**audit-reachable** — source commitment を発行し、検証済み ingress クレデンシャルを保持する conformance class。データセットレベルの系譜を事後監査可能にする。

**boundary translation** — 外部エコシステムのクレデンシャルを、その内容を dPLaaX FirstDrop として再署名して取り込むこと。外部クレデンシャル自体の検証は取り込み時点で attest される。チェーンを過去方向に延長するものではない。

**enrichment** — トリガーとなったイベントに side-fetch した外部データを join する chain-preserving な境界。

**aggregation** — プールされた入力集合を 1 出力にたたみ込むこと。結果はどの単一入力とも同一性関係を持たないため、FirstDrop として新しいチェーンを開始する。

## コンポーネント

**Pipeline Component** — パイプラインに参加するピア。コンポーネント型は*定義特性*のカタログを成し、特権的な型は存在しない。パイプラインはそれらの自由なグラフ合成である。

**FilterConvert** — ステートレスなイベント単位変換で定義される型: 準拠入力イベント 1 つに対し出力 1 つ、チェーンは保持される。

**Origin Source** — FirstDrop の発行で定義される型: 外部取り込み・集約・生成的派生を問わず、データが来歴モデルに入る場所。

**External Sink** — チェーンの終端で定義される型: 検証済みデータを（検証 verdict とともに）外界に提示する。

**Custom** — 少なくとも一方の I/O 側で Pipeline Contract に準拠しつつ、他のカタログ定義に収まらないことで定義される型。

**Pipeline Contract** — コンポーネントが参加するために満たすべきインターフェース義務: ingress をどう検証するか、egress で何を attest するか、監査のために何を保持するか。

**IngressVCStore** — 検証に付随する保持義務: ingress クレデンシャルを検証するコンポーネントはそれを永続化しなければならない。保存なき検証はチェーン監査を壊す。

## アイデンティティと信頼

**did:dplaax** — プロトコルの DID メソッド。DID を運用するレジストリが識別子の中に名指しされるため、環境と運用者は out-of-band の知識ではなくアイデンティティの一部となる。

**Owner DID / Pipeline DID / Process DID** — アイデンティティ階層: Owner（責任を負う組織）が Pipeline（デプロイされたフロー）を管理し、Pipeline が Process（署名境界）を管理する。クレデンシャルは Process レベルで署名され、責任は階層を上向きに解決される。

**DelegationCredential** — スコープ付きの権限がアイデンティティ階層を下って委譲されたことを assert する owner 署名のクレデンシャル。検証者は署名の背後の controller chain を再構成できる。

**Data Integrity proof** — クレデンシャルの署名に使う W3C の proof 形式。proof は署名スコープの外に付加され、使用した cryptosuite と verification method を名指しする。

**cryptosuite** — canonicalization と署名方式の名前付き・バージョン付きの組。suite は proof 作成時刻で評価される明示的なライフサイクルを持ち、suite の老朽化に応じて検証結果は予測可能に縮退する。未知または no-op の suite は fail-closed。

**canonicalization** — ハッシュ・署名の前にドキュメントを還元する決定的なバイト形。意味的に等しいドキュメントが等しいバイト列に commit することを保証する。

**confidence** — チェーンの検証結果意味論: 軸ごとの verdict は最弱リンクで合成され、「検証できなかった」は「失敗が証明された」と区別される。

**organization verification** — DID を実世界の運用者に結びつける out-of-band の endorsement（例: 運用者ドメイン配下の DNS レコード）。クレデンシャル confidence とは直交する: 署名者を誰と信じるかを変えるのであって、チェーンが検証できるかを変えるのではない。

**transparency log** — 発行済み成果物に対する inclusion / consistency proof を提供する任意の append-only ログ層。発行者やレジストリによる遡及的すり替えに対して監査を強化する。
