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
