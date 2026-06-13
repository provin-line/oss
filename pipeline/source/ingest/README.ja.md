# ingest — Source Process メカニクス: 外部インジェスト
> 日本語版 — English: [README.md](README.md)

パイプラインネットワーク外からのインジェスト。トリガーが Pipeline-conformant な前イベントになることはない（HTTP push・ファイル到着・poll・非準拠な外部クレデンシャルの到着）ため、トリガー規則により発行されるクレデンシャルは FirstDrop — 純粋なチェーンオリジンである。

**Boundary translation** はこのメカニクスの特殊形: 外部 ecosystem クレデンシャル（SCITT・GAIA-X 等）が到着し、アダプタ自身のロジックで検証された後、dplaax の FirstDrop として再署名される。外部クレデンシャルへのリンクはデータペイロードの関心事であり、クレデンシャルフィールドにはしない。

## External DID Source pattern

boundary translation の DID-source 形、の契約。トリガーは foreign DID method（`did:webvh`・`did:web` 等）で署名された credential の到着。取り込み process は:

1. foreign DID を解決し、外部 credential の署名を**取り込み時に**検証する — point-in-time の解決が構造的に十分である唯一の地点;
2. **payload** に取り込み証拠を載せた FirstDrop を発行する。証拠は登録済み ingestion schema（SchemaRef が pin）に従う: 外部 credential（または digest）、検証に使った解決素材、判定、検証時刻。解決素材を同梱することで署名検証は永久にオフライン再実行可能になり、取り込み者の帰責対象として残る主張は「その素材が当時本当に提供されていたこと」だけになる;
3. claim は `provin:convert`（boundary translation の定石）。

これは**帰責可能な boundary translation であって、監査の継続ではない**: chain は後方に延びず、`derived_from` が foreign 発行者を名指すことはなく、外部入力の責任は取り込み Owner で終端する（audit.attribution.origin-default）。「どのシステムから入ったか」は ingestion schema の必須フィールドが答える — hash 束縛された payload、schema 統治、credential field ではない。鍵履歴を持つ source method（T2）は attest された検証を独立に再確認可能にし、T3 source では文書真正性の主張が取り込み者の帰責に乗る（GLOSSARY の DID method tiers 参照）。

## 参照実装：apipush/

HTTP プッシュエンドポイント（`POST /push`、JSON のみ、ボディサイズ上限あり）がプロセスの入力キューにパブリッシュし、`GET /health` も提供する。署名パスに関する注記：HTTP エンドポイントはトランスポートアダプタ（Subscriber）であり、生のペイロードを下流の **Source Process** ランタイム — [`ingest.go`](ingest.go) の FirstDrop 署名器 — に向けてパブリッシュする。この署名器は何も検証せず（`VerificationNone` は Source の定義そのもの）、バイト列をそのまま署名する。エンドポイントと署名器を1つのプロセスに融合した自己完結型バリアントも同様に `pipeline/contract` に準拠する。

署名ランタイムは設計上 **transform-free**：filter / convert / enrich は Chained Process の責務であり、boundary translation の再整形はバイト列が署名器に届く*前*にアダプタ自身のロジックで行う（上記）。Source に変換を持たせると、対称性で Sink にも同じことが起き、Source / Chained / Sink の区別が何でも屋の単一プロセスへと崩れる。

その他の外部ソースメカニクス（ファイルリーダー、スケジューラ・ポーラー、アーカイブリプレイ）も同じ形状に従い、ここまたは拡張リポジトリに置かれる。
