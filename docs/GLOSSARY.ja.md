# 用語集

> 日本語版 — English: [GLOSSARY.md](GLOSSARY.md)

定義は**責務ベース**: 各項目はその用語が*何であり*、何を保証するかだけを述べ、現状の実装値（カタログの中身、個数、アルゴリズム選択、ワイヤ上のリテラル）は書かない。具体値は package の契約と dPLaaX spec が正本であり、本ファイルはそれらと共に drift してはならない。

## プロトコルと命名

**dPLaaX** — 本リポジトリが実装するプロトコル。すべてのデータ変換を署名付きクレデンシャルとして attest し、検証可能な来歴チェーンを形成する。ワイヤ名前空間（proto パッケージ、DID メソッド、protocol JSON-LD context）はプロトコルが所有し、実装からは独立している。

**provin** — プロダクト。本リポジトリで保守される dPLaaX の参照 *wire profile*。この名前は成果物（リポジトリ、CLI、イメージ）と profile の拡張名前空間にのみ現れ、プロトコルのワイヤ名前空間には決して現れない。

**wire profile** — dPLaaX wire spec と具体実装の間にある宣言レイヤー。profile はどのプロトコルカタログを採用するかを宣言し、プロトコルの default を狭めたり厳しくしたりでき、namespace-prefix 付きの拡張を追加できる。プロトコルが文法のみを釘付けする領域（transformationClaim）では、profile が意味論を全面的に所有する。プロトコル規範には矛盾してはならない。

## クレデンシャルとチェーン

**PipelinePassCredential (PPC)** — パイプライン層の唯一のクレデンシャル型。1 つのプロセス境界が入力を消費し出力を生成したことを attest する Verifiable Credential。subject はコンテンツハッシュと宣言を運び、payload 自体は決して運ばない。

**来歴チェーン (provenance chain)** — `previousCredential` で連結された PPC の厳密に線形な列。各リンクの先行はちょうど 0 または 1。線形チェーンで表現できない系譜は、チェーンを分岐させるのではなく origin 境界で扱う。

**content commitment** — 成果物を名前やロケータではなく、canonical なバイト形のハッシュで参照すること。チェーンリンクが content commitment を使うのは、長期監査がレジストリの生存に依存しないようにするため。commitment が証明するのは完全性であって機密性ではない: 低エントロピーな値空間（boolean の判定、小さな enum）の digest は、空間を列挙できる観察者には辞書攻撃で復元可能。よって内容を推測不能に保つ必要がある payload は、issuer が選んだ salt を payload バイト内に含める — これは payload schema の関心事であり、wire 形状は変わらない（spec の credential.subject.output-hash notes 参照）。

**previousCredential** — PPC のチェーンリンクフィールド。先行クレデンシャルへの content commitment。不在はその credential が FirstDrop であることを示す。

**FirstDrop** — 先行を持たない PPC。チェーンの起点であり、このモデルの意図的な信頼境界。FirstDrop は「誰が・どのスキーマで・どのバイト列を発行したか」を attest し、取り込み以前の世界については何も主張しない。

**トリガー規則 (trigger rule)** — チェーン位相を決める規範的基準: 境界の実行が単一の準拠先行イベントの到着によってトリガーされた場合に限り chain-preserving。それ以外のトリガーはすべて FirstDrop となる。

**データフロー不変量 (data-flow invariant)** — 各クレデンシャルの出力ハッシュが後続の入力ハッシュと一致するという保証。検証者は payload を読み直さずにチェーン全体のバイトレベル連続性を証明できる。

**payload** — パイプラインを流れる実データ。ハッシュでクレデンシャルに束縛され完全性保護されるが、credential 層に埋め込まれることも、そこから復元・解釈されることもない。

**payload delivery mode** — payload バイトの運び方の購読ごとの合意: *inline*（バイトが envelope に同乗）または *by-reference*（hash のみの envelope。subscriber が content hash で publisher の serving 境界へ取りに行く。来歴だけ欲しい consumer は fetch しない）。登録時に交渉され、購読ごとに不変、デフォルトは by-reference。検証はモードに依存しない — hash 束縛により、バイトはどの経路で届いても証明可能。

**transformationClaim** — 出力の情報源についての境界の主張: 申告した入力が出力の情報源の全てか（閉世界 — 申告集合に無いものは寄与していないという除外推論を許す）否か。プロトコルが釘付けするのは文法（単一の namespace prefix 付き token）と開世界デフォルト（未認識の claim から閉世界推論を引き出さない）のみで、各 claim の意味は profile が釘付けする（`vc.TransformationClaim` レジストリ）。claim の同一性は (接地 URL, label) の組 — namespace prefix は @context 内の context で接地され、偽装 prefix は署名スコープ内のバイト列で区別可能。署名者による宣言であり機械検証される性質ではない — 監査価値は主張への帰責にある。claim は位相を拘束しない。

**SchemaRef** — 出力の登録済みスキーマへの content-commit された参照。スキーマの遡及的改変を暗号学的に検出可能にする。

**SourceCommitment** — 任意のクレデンシャルが運べる attest。境界が消費した準拠 source クレデンシャル全集合への commitment（chain-preserving ではトリガーの先行イベントも含む — 全消費分セマンティクス）。*監査属性*であって親リンクではない: チェーンは線形のままであり、外界からの読み取りは意図的にスコープ外。

**source_root** — SourceCommitment 内の Merkle set commitment。消費した source クレデンシャル群への、順序非依存でコンパクトな commitment。source ごとの inclusion proof を支える。

**audit-reachable** — source commitment を発行し、検証済み ingress クレデンシャルを保持する conformance class。データセットレベルの系譜を事後監査可能にする。

**boundary translation** — 外部エコシステムのクレデンシャルを、その内容を dPLaaX FirstDrop として再署名して取り込むこと。外部クレデンシャル自体の検証は取り込み時点で attest される。チェーンを過去方向に延長するものではない。

**DID method tiers (T1/T2/T3)** — DID method の解決が*時間を超えて*何を証明できるかの文書語彙。T1 = `did:dplaax`（federation 統治 registry・append-only lifecycle 記録・組織検証）— credential 発行面に許される唯一の method。T2 = `did:webvh` / `did:tdw`（自己ホスト・改竄検出可能な鍵履歴）— 遡及検証可能。T3 = `did:web`（現在状態のみ・履歴なし）— point-in-time でのみ十分。tier は認証面の deployment policy の判断材料であり、external-DID-source ingestion の証拠強度を修飾する。語彙であって型レベルの契約ではない。

**enrichment** — トリガーとなったイベントに side-fetch した外部データを join する chain-preserving な境界。

**aggregation** — プールされた入力集合を 1 出力にたたみ込むこと。出力が FirstDrop になるのは実行が単一の適合イベントにトリガーされないため（トリガー規則が規範）。どの単一入力とも同一性関係を持たないことは根拠であって判定基準ではない。

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

**Owner identity binding (`alsoKnownAs`)** — did:dplaax の Owner と組織の対外 identity（例: `did:web`）が同一当事者であることを述べるパターン。意味を持つのは**双方向**の場合のみ — 双方の DID 文書が互いを名指しする状態を*確立*できるのは、両文書を支配する当事者だけである。それでも束縛されるのは文書の支配までであり、法人としての同一性ではない — Owner と法人の権威ある束縛は federation registry の組織検証（T1）が担う。後の解決が証明するのは「Owner が alias を維持している」かつ「*現在の* domain 支配者が逆 pointer を主張している」まで — 乗っ取られた domain でも双方向束縛は新鮮に見え続ける。だから監査の baseline は再解決ではなく registry-witnessed snapshot（束縛が registry に提出された時点 — 登録時または後続の lifecycle event — で記録される）である。registry に一度も提出されなかった束縛は self-asserted のままで、witnessed baseline を持たない。依拠者は依拠した内容を snapshot し（L2 登録と同様）、監査感応の deployment は鍵履歴で連続性を検証できる T2 method を選好する。束縛は **attribution を一切動かさない**: 責任は alias の有無に関わらず did:dplaax Owner に対して計算される（`audit.attribution.*`）ため、domain の消失・乗っ取りの影響は alias・認証層に留まる。equivalence registry は存在しない。束縛の追加・rotation・消失は federation registry の append-only lifecycle log に記録される lifecycle event である。

**DelegationCredential** — スコープ付きの権限がアイデンティティ階層を下って委譲されたことを assert する owner 署名のクレデンシャル。検証者は署名の背後の controller chain を再構成できる。

**Data Integrity proof** — クレデンシャルの署名に使う W3C の proof 形式。proof は署名スコープの外に付加され、使用した cryptosuite と verification method を名指しする。

**cryptosuite** — canonicalization と署名方式の名前付き・バージョン付きの組。suite は proof 作成時刻で評価される明示的なライフサイクルを持ち、suite の老朽化に応じて検証結果は予測可能に縮退する。未知または no-op の suite は fail-closed。

**canonicalization** — ハッシュ・署名の前にドキュメントを還元する決定的なバイト形。意味的に等しいドキュメントが等しいバイト列に commit することを保証する。

**confidence** — チェーンの検証結果意味論: 軸ごとの verdict は最弱リンクで合成され、「検証できなかった」は「失敗が証明された」と区別される。

**organization verification** — DID を実世界の運用者に結びつける out-of-band の endorsement（例: 運用者ドメイン配下の DNS レコード）。クレデンシャル confidence とは直交する: 署名者を誰と信じるかを変えるのであって、チェーンが検証できるかを変えるのではない。

**transparency log** — 発行済み成果物に対する inclusion / consistency proof を提供する任意の append-only ログ層。発行者やレジストリによる遡及的すり替えに対して監査を強化する。
