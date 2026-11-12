# conformance/ — provin profile 適合性 artifact
> 日本語版 — English: [README.md](README.md)

**provin wire profile** の機械検証可能な事実をデータとして固定し、
`go test ./conformance/` が本実装に対して実行する。

**本ディレクトリに規範の散文は置かず、規範の再表現もしない。** SoT は以下:

| 規範 | SoT |
|---|---|
| dPLaaX protocol 規則（claim 文法・接地・開世界デフォルト等） | `dplaax.spec` の rule catalog（`rules/` + `schemas/` + `vectors/`） |
| provin claim registry と各 claim の意味（closed / conformant-closed / open） | [vc/credential.go](../vc/credential.go)（`TransformationClaim` registry の doc comment）+ [vc/README.ja.md](../vc/README.ja.md) |
| provin profile context 文書（byte 単位で正規） | [vc/contexts/provin-v1.jsonld](../vc/contexts/provin-v1.jsonld) |

## vector が固定するもの

- `vectors/claim-*.json` — registry の各 claim について: wire トークンが文法適合
  であること、実装が profile の `@context` リストを正確に emit すること、接地
  チェックが受理すること、展開が固定された語彙 IRI に一致すること
  （claim の同一性 = (接地 URL, label) の組）。
- `vectors/context-001.json` — profile context 文書の byte 台帳: sha256、
  文書が担う prefix 接地、`@protected`。文書バイトの変更は意図的な行為であり、
  同一変更内で台帳を更新しなければ harness が fail する。

vector の形状は `dplaax.spec` の vector 規約に従う。`instantiates` field は
その vector が行使する protocol rule id への参照 — 情報提供であり、protocol 側
vector 集合への所属を主張するものではない。

claim ごとの*意味*は署名者による宣言（帰責のための claim であり、機械検証される
性質ではない）ため、vector には意図的に**含めない** — ここに複製すると第二の
SoT が生まれる。

## dplaax protocol vectors（vendored）

`vectors/dplaax/` は protocol 自身の conformance vector catalog
（`dplaax.spec` `vectors/`、全 corpus）を byte-exact に
vendoring し、`MANIFEST.sha256` で pin する。manifest テストは in-place 編集で
fail する — spec 変更の取り込みは意図的な行為であり、
`scripts/sync-spec-vectors.sh` を実行して vendored diff ごと commit する。

CI が実行する入口は `TestDplaaxAllVectors`（`allvectors_test.go`）1 つ。まず
`MANIFEST.sha256` に対して台帳が欠けていないことを確かめる — どの vector も
runner（`dplaaxRunners`）か理由付きの skip（`dplaaxSkips`）のちょうど一方を持ち、
manifest に無い vector を台帳が名指さない。それから vector ごとに subtest を
実行する。driver も skip の理由も無い vector が同期されて入ると harness が落ちる。
完全さの確かめ（`checkCoverage`、`TestCheckCoverage` が固定する）は静的な map と
manifest だけを読むので、`-run 'TestDplaaxAllVectors/canon'` で一部だけを実行しても
guard は落ちない。実行: `make conformance`、または
`go test ./conformance/ -run TestDplaaxAllVectors`。

**合計 235 本: 実行 199 本、理由付きの skip 36 本。** driver の詳細は
README.md（英語版）の表を参照。

**第 1 弾（166 本、純関数系。runner は `dplaax_test.go`、`did_test.go`、
`keybinding_test.go`、`evidenceview_test.go`）**: canon-001..008 /
cred-001..032（strict decode + `ValidateWireForm` — data-integrity 軸が委譲する
単一実装）/ commitment-001..011, 013 / chain-006..008（continuity、DataIntegrity 軸）/
confidence-001..006（lifecycle は effectiveDate を時間シフトして実 Verify 駆動）/
delegation-001..005（`Build` で再署名して `Verify`）/ delegation-006..008（同じ再署名で、vector の `target` に対して `VerifyFor`）/ did-001..031（`did/dplaax.Parse` が受けるか。受けたものは `IsOwner`・`IsPipeline`・`IsProcess` の level、`OwnerDID`、`Pipeline`: Process には Pipeline があり、ほかの level には無い）/ keybinding-001..054（proof が名指す検証の鍵で eddsa-jcs-2022 の proof に署名し直し、足すのは proof-local の `@context` と `proofValue` だけ。ほかの member は `created` も含めて書かれたまま署名する。dplaax の `vectors/README.md` の「Fixture proofs」。そのあと `keybinding.Verifier` に通す: binding は `RestoreStatusList`（verifier が保持する list）の後に `VerifyBinding`、保持する list に対する list は `RestoreStatusList` の後に `VerifyStatusList`、list だけなら `VerifyStatusList`、content hash は `StatusListContentHash`）/ signer-001..003 / identity-001..002（`Hash`（body address）と `WireVariantID` を catalog が規則の文から導いた hash に対して。proof を発行し直しても body address は動かず、variant id は分かれる）/ evidence-view-001..002（`appraisal.View` の manifest の正規の byte と `evidenceViewId`。id が合わない view は `appraisal.ErrViewIDMismatch`）/ claims-coverage-001..004（`appraisal.View.ValidateShape` が受けるか。`appraisal.Decide` が vector の禁じる decision に至らないこと）/ claims-policy-001（`appraisal.Decide` が vector の名指す decision に至ること）。

**第 2 弾（33 本、実物の seam に対する挙動系。runner は `tranche2_test.go` と
`didresolution_test.go`）**: commitment-012（`vcresolver/filestore` の永続:
再起動の後に Get が解決する）/ resolver-001..003, 008（`Hash` の content
address）/ resolver-004..005, 009（権威で分けた状態から確信度への写し）/
registry-001..002（`yamlstore` の append-only と、deprecate が body を残すこと）/
chain-001..005（trigger と `PreviousCredential` の wire の形）/ audit-001..004（実物の
`vc.Verifier.AttributeOwner`）/ process-004（`sink.Processor` が外への書き込みの前に
受けた credential を確かめること）/ process-005..006（receipt の wire の形と同一性）/
identity-003..007（実物の `vcresolver.VariantStore`: write-once と append-only の
variant、body だけの legacy の写し、同じ id で別の byte を返す store の拒否）/
transfer-001..004（発出の log と受け入れの store の content hash の join key、
`filelog` の改ざん検出、受けた credential と関係の記録が再起動の後も残ること）/
did-resolution-id-mismatch-001・did-resolution-unavailable-001（外向きの resolver
`network/pkg/didresolver`: 別の id の文書は `ErrDIDIdentityMismatch`、registry の
5xx は一時の失敗）。

**拒否の vector は、規則が名指す sentinel で断られた時だけ通る（規則にまだ
sentinel が無いものは、断りの文の一部で）。** `keybinding-*` の
拒否の vector は vector ごとに sentinel と断る段に結ぶ。restore の段で断るのは、
判定の時より後の日付の list を持つ `keybinding-023` だけで、ほかの binding の
vector の list は restore できなければならない。`did-008..021`
（`did.dplaax.syntax`）は `did/dplaax.ErrSyntax` に結ぶ。`delegation-007..008` は
`delegation.ErrNotForIdentity` に、`delegation-002..005` は、`delegation` に
その規則の sentinel ができるまで error の文の一部に結ぶ。`claims-coverage-002`
と `-004` は `appraisal.ErrInvalidVector` に結び、decode できない view はその
vector を落とす。どの表も manifest の拒否の vector をちょうど覆うことを guard の
試験が確かめる。

**理由付きの skip（36 本）**:

- `resolver-006` — 構造で強制（P0-11）: `vcresolver.VariantStore` にも、その下の
  `VariantBackend` にも、追い出し・削除の口が無いので、禁じられた
  Resolved→NotFound の遷移は作れない。vector は、追い出しの口ができた時の形の
  pin として残す。
- `resolver-007` — 予約（P0-11）: `resolver.batch.shape` は、実装や profile が
  足す batch の lookup の口を縛るが、口を持つことは求めない。`dplaax.vc.v1` は
  それを定めない。
- `process-001..003` — 未着手: process の型・挙動の classifier の口が無い
  （4 つの型の catalog は deployment の静的な属性で、呼べる classifier ではない）。
- `auth-grant-kid-mismatch-001`、`auth-grant-legacy-no-method-001`、
  `auth-grant-legacy-no-method-ambiguous-001` — `/oauth/token` の L1 の DID grant
  の JWS の経路: この repo に JWS の grant の口は無い。provin-line/auth がこれらを
  vendoring して自分の conformance harness で実行する。
- `claims-effect-001..002` — 未着手: effect の scope の写しと legacy の receipt の
  写しが無い。どちらも P0-5 の外部 effect の gate の口で、まだ実装していない。
- `effect-001..013` — 未着手: 外部 effect の gate が無い。P0-5 の対象
  （ReleaseAuthorization、quarantine の entry、ObservationRecord・DecisionRecord、
  effect の状態機械）は spec だけ。
- `release-001..013` — 未着手: この repo に release の pipeline が無い。P0-7 の
  対象（evidence manifest、advisory の評価、waiver、scan・build の状態機械）は
  CI・release の基盤で、library の code ではない。

第 2 弾の driver が、実装が呼べる関数ではなく構造として持つ規則を組み立て直す所
（chain の trigger の分類 — chain.trigger.retention の notes のとおり、wire の写しが
定まった適合の義務である）では、そのことを driver の comment に書く: harness は、
届く実物の部品に対して vector を固定する。
