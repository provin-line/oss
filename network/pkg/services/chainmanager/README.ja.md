# chainmanager — パイプラインチェーン接続管理
> 日本語版 — English: [README.md](README.md)

全クロスパイプライン接続のコントロールプレーン。すべてのネットワークで必須。1 つのサービスが 2 つの異なるサーフェスを提供する:

| Surface | Service | Auth | RPCs |
|---|---|---|---|
| オペレーター向け | ChainService | L1 JWT | Subscribe / Unsubscribe / ListSubscriptions / UpdateAllowList |
| インターネット向け | ChainPeerService | **L2 wireauth のみ** | GetPublisherInfo / RegisterSubscription / Disconnect |

## 接続フロー（サブスクライバー起点）

1. オペレーターがサブスクライバーの chainmanager に対して `Subscribe` を呼び出す。
2. サブスクライバー CM はパブリッシャーの DID ドキュメント（`#chain-manager` エンドポイント）を解決し、エンドポイント URL を検証（SSRF ガード）したうえで、パブリッシャー CM に対して `GetPublisherInfo`（軽量許可リストチェック）と `RegisterSubscription`（フル許可リスト + L2 署名）を呼び出す。
3. 双方が自身の `InfraOperator` を駆動してトランスポートをワイヤリングする（パブリッシャー: エクスポート; サブスクライバー: インポート）。

許可リストは DID グロブパターンで定義し、トラストモデルはデフォルト不信 / オプトイン。

## infra/ — トランスポート抽象

`InfraOperator`（AddExport / RemoveExport / AddImport / RemoveImport / PublishType）は、pub-sub バックエンドの Hub スワップポイントである。実装:

- `nats/` — 動的 NATS アカウントクレーム JWT 管理（フルリゾルバーモード必須）
- `noop/` — デバッグ/テスト専用; 非デバッグビルドでのワイヤリングは不可能でなければならない

## wireauth/ — L2 ピア認証

ChainPeerService のすべての RPC は `AuthProof` を持つ: JCS 正規化された RPC ごとのビュー（オペレーション識別子 + ビューバージョン + ノンス + issuedAt + ビジネスフィールド）に対する Ed25519 署名。検証は順序付きパイプライン — 安価なフェイルファストチェックを先に行い、署名検証を後回しにし、ノンスの記録は署名成功後のみ行う（失敗した偽造によって正規の署名者のノンスが消費されてはならない）:

1. プルーフ欠如フェイルファスト → 2. issuedAt 切り捨て → 3. 再起動エポックバリア →
4. 受け入れウィンドウ（非対称な過去/スキュー） → 5. DID ドキュメント経由の鍵解決
（`#auth-key`、authentication リレーションシップ + コントローラー一致） → 6. 署名者-アクター認可 → 7. 正規バイト再構築 → 8. Ed25519 検証 → 9. ノンス記録。

インメモリノンスストア + 再起動エポックバリアは許容された PoC 実装（永続ノンスストアはドキュメント化済みのフォローアップ）。すべての wireauth 失敗は型付きセンチネルエラーであり、ハンドラーが `errors.Is` でマッピングする。
