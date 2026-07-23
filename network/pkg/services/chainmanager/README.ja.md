# chainmanager — パイプラインチェーン接続管理
> 日本語版 — English: [README.md](README.md)

全クロスパイプライン接続のコントロールプレーン。すべてのネットワークで必須。1 つのサービスが 2 つの異なるサーフェスを提供する:

| Surface | Service | Auth | RPCs |
|---|---|---|---|
| オペレーター向け | ChainService | L1 JWT | Subscribe / Unsubscribe / ListSubscriptions / UpdateAllowList |
| インターネット向け | ChainPeerService | **L2 wireauth のみ** | GetPublisherInfo / RegisterSubscription / Disconnect |

## 接続フロー（サブスクライバー起点）

1. オペレーターがサブスクライバーの chainmanager に対して `Subscribe` を呼び出す。
2. サブスクライバー CM はパブリッシャーの DID ドキュメント（`#chain-manager` エンドポイント）を解決し、エンドポイント URL を検証（SSRF ガード）したうえで、パブリッシャー CM に対して `GetPublisherInfo`（軽量許可リストチェック + パブリッシャーの提供 payload 配送モード）と `RegisterSubscription`（フル許可リスト + L2 署名。署名ビューに要求 payload 配送モードが入り、要求は否認不能になる — パブリッシャーが提供しないモードはこの段階で typed エラーとして拒否され、実行時の silent fallback は起きない）を呼び出す。
3. 双方が自身の `InfraOperator` を駆動してトランスポートをワイヤリングする（パブリッシャー: エクスポート; サブスクライバー: インポート）。合意済み payload 配送モードはエクスポート境界で適用される。

許可リストは DID グロブパターンで定義し、トラストモデルはデフォルト不信 / オプトイン。

payload 配送（`inline` / `by-reference`、デフォルト `by-reference`）は購読ごとに合意され、購読の生存期間中は不変 — モード変更 = 新規購読。`Subscription` record の契約（`store/`）と `Envelope` の契約（`pipeline/contract`）を参照。

**empty-mode 互換性についての注意**: 未指定のリクエストモードは inline ではなく by-reference に正規化される。serving するパブリッシャーは now genuinely by-reference を提供する（後述）ため、以前は typed rejection だった empty/未指定モードのリクエストが、現在は by-reference 合意として**成立する**。これは互換エイリアスではなく挙動変更である: consumer 側は by-reference 用に構成されていなければならない（`payload-delivery = "by-reference"` config key + `PayloadResolver`）— さもなければ ingress は全イベントを配送違反として reject する。inline を望む古いクライアントは明示的にリクエストする必要がある — モード省略はもはや「inline をくれ」を意味しない。

## モードスコープ export subject と subscriber 側 rename

export seam は飛行中の NATS メッセージを変換できない（account の export/import はルーティング権限であり payload の変換ではない）ため、合意済み payload 配送モードを**構造的に**適用する — モードを個別の wire subject へ写像することによって:

- `subjectForMode(publisherDID, mode)`（service 内部）: `inline` は plain な `publisherDID` を export し、`by-reference` は `"byref." + publisherDID`（`ByReferenceSubjectPrefix` — 生産ループ（`pipeline/runtime/dataplane.go`、`wireprofile` のエイリアス経由）が dual-emit stripped-form publish を全く同じ subject へ bind できるよう export 済み定数。prefix 規約の重複を避ける）を export する。suffix ではなく prefix である理由: dplaax DID の registry セグメント自体がドットを含み得るため、suffix 方式では「該当セグメントで終わる DID」との衝突を文法証明なしに排除できない；prefix なら先頭 token で綺麗に分離できる。この関数は `publisherDID` の NATS-subject 安全性検証も兼ねる（whitespace / `*` / `>` / 空 dot セグメントはすべて `ErrUnsafeSubject` で fail-closed）— `requirePipelineDID` は DID の形を証明するのみで、wire subject としての安全性は証明しない。
- パブリッシャー側の export ref-count は `publisherDID` ではなく**export された subject**をキーにする: 同一パブリッシャーへの inline 購読と by-reference 購読は異なる subject を export し、独立に ref-count される — 片方の teardown がもう片方の export に触れることはなく、同一モード/subject の 2 subscriber は 1 つの export を共有する（`AddExport` は idempotent）。
- **teardown は保存された subject から駆動する（再計算しない）**: `Disconnect` は `sub.ConnectionInfo["subject"]`（登録時に `AddExport` が実際に返した subject）を削除する。`PayloadDelivery`/`subjectForMode` から再導出することはない。これにより legacy record の teardown も正しく動作する: この mode 適用が入る前に作られたすべての購読は、合意モードに関わらず PLAIN subject で export されていた（export seam がまだモードを適用していなかった）ため、`ConnectionInfo["subject"]` こそが削除すべき対象であり、現在の写像が計算する値ではない。保存 subject が欠落したレコードは破損状態であり、`Disconnect` は推測せず fail-closed（`ErrExportSubjectMissing`）する。
- **subscriber 側の rename**: `Subscribe` の `AddImport` は remote subject を、常に plain な `publisherDID` である LOCAL subject へ rename する — inline の remote は既に `publisherDID`（rename は no-op）、by-reference の remote は `"byref." + publisherDID` で plain DID へ rename し直す。consuming loop の `ingress-subject` config はモードに依らない: `"byref."` prefix を知る必要は一切なく、購読のモードが変わっても（モードは購読ごと immutable なので新規購読になる）loop config に触れる必要がない。
- **mixed-mode invariant**: 両モードの remote が同一 local subject に rename されるため、同一 subscriber account が同一パブリッシャーへの inline と by-reference の購読を同時に持つと、1 つの local subject に両形式が届いてしまう（重複処理 + 配送違反 reject）。両側で強制する: `Subscribe`（subscriber 側、authoritative）は、既に何らかのモードで購読済みのパブリッシャーへの 2 回目の購読を拒否する（`ErrDuplicateSubscription` — モード変更は Unsubscribe → 再 Subscribe）；`RegisterSubscription`（publisher 側、defense-in-depth）は、(subscriberDID, publisherDID) の組が既に**異なる**モードで登録されている場合の登録を拒否する（`ErrMixedModeSubscription`）。異なる subscriber は同一パブリッシャーへ異なるモードを自由に保持できる — invariant は 1 つの subscriber/publisher 組にスコープされ、パブリッシャー単体ではない。
- **legacy な保存済み by-reference 購読のアップグレード手順**: この slice 以前に登録された購読で、保存モードが by-reference（または空 — 従来のデフォルト）を示すものは、実際には plain subject で export されていた。データパスは自動移行しない（モードは購読ごと immutable — PoC ポスチャ）。実際の by-reference 配送を得るには: 旧購読を subscriber 側から `Unsubscribe`（publisher 側の `Disconnect` を駆動し、上記の保存 subject 起点 teardown により plain export を漏れなく撤去）してから、明示的に `"by-reference"` を指定して再 `Subscribe` する。

## infra/ — トランスポート抽象

`InfraOperator`（AddExport / RemoveExport / AddImport / RemoveImport / PublishType）は、pub-sub バックエンドの Hub スワップポイントである。実装:

- `nats/` — 動的 NATS アカウントクレーム JWT 管理（フルリゾルバーモード必須）
- `noop/` — デバッグ/テスト専用; 非デバッグビルドでのワイヤリングは不可能でなければならない

## wireauth/ — L2 ピア認証

ChainPeerService のすべての RPC は `AuthProof` を持つ: JCS 正規化された RPC ごとのビュー（オペレーション識別子 + ビューバージョン + ノンス + issuedAt + ビジネスフィールド）に対する Ed25519 署名。検証は順序付きパイプライン — 安価なフェイルファストチェックを先に行い、署名検証を後回しにし、ノンスの記録は署名成功後のみ行う（失敗した偽造によって正規の署名者のノンスが消費されてはならない）:

1. プルーフ欠如フェイルファスト → 2. issuedAt 切り捨て → 3. 再起動エポックバリア →
4. 受け入れウィンドウ（非対称な過去/スキュー） → 5. DID ドキュメント経由の鍵解決
（`#auth`、authentication リレーションシップ + コントローラー一致） → 6. 署名者-アクター認可 → 7. 正規バイト再構築 → 8. Ed25519 検証 → 9. ノンス記録。

**L2 identity と監査期間。** 署名ビューは呼び出し瞬間のアクセス制御だが、保存された記録は監査期間にわたる監査証拠を兼ねる。deployment が L2 当事者に web アンカー系 DID method（例: did:web の consumer）を許す場合、CM は署名ビューと並べて「解決した DID document のスナップショット（鍵束縛）」を tlog に記録する — 署名はスナップショット内の鍵に対して永久に再検証可能になり、残る主張は「その束縛が登録時に本当に提供されていたか」だけになる。検証可能な鍵履歴を持つ method はその残余も閉じる。監査感度の高い deployment は L2 当事者を T1/T2 に制限する（GLOSSARY の DID method tiers 参照）。

インメモリノンスストア + 再起動エポックバリアは許容された PoC 実装（永続ノンスストアはドキュメント化済みのフォローアップ）。すべての wireauth 失敗は型付きセンチネルエラーであり、ハンドラーが `errors.Is` でマッピングする。
