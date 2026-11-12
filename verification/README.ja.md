# verification — provin OSS の形式モデルと標準 vector
> 日本語版 — English: [README.md](README.md)

この directory は test 専用の Go module（`github.com/provin-line/oss/verification`）で、
provin OSS を形式モデルと第三者の標準の test vector に照らして確かめる。
production code は持たず、root の module の外にある: root の `go test ./...` は
ここに入らない。実装の security の性質 2 つの Tamarin model と、[`vectors/`](vectors)
の標準 vector（[下](#標準-vector)）を持つ:

| model | 道具 | 対象 |
| --- | --- | --- |
| [`tamarin/wireauth.spthy`](tamarin/wireauth.spthy) | Tamarin 1.12.0（Maude 3.5.1） | L2 の peer wire 証明（[auth.ja.md § L2](../docs/protocol/auth.ja.md#l2--peer-wire-証明wireauth)）: 署名した view とその audience、一度きりの nonce、署名が通った後にだけ記録される nonce |
| [`tamarin/bearerorigins.spthy`](tamarin/bearerorigins.spthy) | Tamarin 1.12.0（Maude 3.5.1） | node が L1 の bearer（`vc-store-bearer`）を誰に見せるか |

dPLaaX protocol そのものの性質（来歴の連鎖、委任）は仕様の repository
`dplaax.spec` の `formal/` で model にしている。ここの model はこの実装のもので、
下の各契約が述べる前提の下で code がしていることを model にし、それが攻撃者に
対して成り立つかを示す。

## `wireauth.spthy` の契約

model は、それを読む前提の分しか意味を持たない。model の header の comment も
同じことを書いている。

- **攻撃者。** network は攻撃者のもの（Dolev-Yao）: どの message も読み、再送し、
  書き換え、組み立てられる。攻撃者は自分の DID を作れ、その DID document には
  正直な署名者の鍵を含め、どの鍵でも載せられる。正直でない受け手の node も
  これに含まれる: 正直な署名者が作る proof はすべて network に出るので、そうした
  node が受け取るものは攻撃者も持つ。
- **信頼する部品。** 検証者（乗っ取られない）、DID の解決（DID の `#auth` 鍵は
  検証者に直接届く）、署名（鍵なしに偽造できない）。
- **侵害を許す部品。** どの署名鍵も（rule `Compromise`。`Compromised(k)` を記録）。
- **nonce。** 正直な署名者は proof ごとに新しい nonce を引く（`wireauth.NewNonce`。
  `wireauth.Sign` の呼び手はすべてこれを使う）。`nonce_names_signing` と `no_burn` はこれに拠る。
- **永続と時間。** 無し。`issuedAt` は view の中の不透明な項。受理の窓、再起動の
  epoch、nonce の掃除、再起動は model の外で、ここの nonce store は忘れない。
  窓を過ぎた後に忘れて安全なことは時間の性質で、まだ書いていない TLA+ の model
  （`NonceEpoch`）に任せる。
- **store。** network process ごとに検証者が 1 つ、nonce store が 1 つ
  （`internal/netcompose/server.go`）。L2 の proof を検証するすべての面が共有する。
  store の `Use` は原子的な check-and-set（restriction `NonceStore`）。
- **audience。** 検証者はそれぞれ audience を 1 つ持つ。それはその node の registry
  ID（D-w12）。view は audience を束ね、検証者は別の audience を名指す proof を断り、
  自分の audience で view を組み直す。1 つの audience を複数の検証者が持ちうる
  （replica。それぞれ自分の store を持つ）。配備は audience ごとに検証者を 1 つに
  する。これが `replay_across_replicas` を閉じる（[auth.ja.md § L2](../docs/protocol/auth.ja.md#l2--peer-wire-証明wireauth)）。
- **要求。** 要求はその op と fields のこと: handler は `Verifier.Verify` に渡した
  fields にだけ基づいて動き、検証者を共有する面の間で op の値は重ならない。正直な
  署名者は、渡された audience・op・issuedAt・fields のどれにでも署名する。
- **事象。** `Accepted(V, R, S, op, n, t, f)`: audience が `R` の検証者 `V` が
  proof を受理した（`Verify` が nil を返し nonce を記録した）。
  `ReplayRejected(...)`: 署名は通ったが nonce が記録済み（`ErrReplay`）。
  `Spend(V, S, n)`: 検証者 `V` が署名者 `S` の nonce `n` を記録した。
- **含めないもの。** fields の値の文法と JCS の bytes（D-w11。test vector と
  fuzz に任せる）、認可（拒否は store を元のままにする。発火しない rule と同じ）、
  DID の綴り（view と store の鍵は同じ文字列を使う）、鍵の rotation。

## `bearerorigins.spthy` の契約

- **攻撃者。** Dolev-Yao。node が取りに行く endpoint（`StoreVC` の呼び手の hint、
  発行者の DID document）と redirect の先をすべて選び、自分の server（乗っ取った
  server）を動かす。
- **信頼する部品。** node。名指しの origin の server への経路（攻撃者は読めず、
  redirect もさせられない）。これは TLS の前提で、`https` の origin では成り立ち、
  `http` の origin はこの前提の外。
- **侵害を許す部品。** どの server も（`CompromiseServer`）。乗っ取られた server は、
  受け取った bearer を前後を問わず攻撃者に渡す。
- **名指しの origin。** operator が設定した宛先（`vc-store-endpoint`、各 loop の
  upstream endpoint）と `credential-origins`。model は両者を区別しない。
- **事象。** `Received(o, tok)`: origin `o` の server が bearer を受け取った。
  `K(tok)`: 攻撃者がそれを知っている。
- **含めないもの。** URL の読み取りと origin の比較（`internal/origin` の試験）、
  transport の強制、CLI の `--token`。

## lemma と実装

`wireauth.spthy`:

| lemma | 種類 | 性質 | 実装 |
| --- | --- | --- | --- |
| `executable_accept` | exists-trace | 正直な DID の proof が、鍵の侵害なしに受理される（到達性） | — |
| `executable_alias` | exists-trace | 1 つの鍵を持つ 2 つの正直な DID が、それぞれ proof を受理される | — |
| `forgery_after_compromise` | exists-trace | 鍵を乗っ取られた正直な DID は、署名していない proof を受理される: `view_binding` の例外は生きている | — |
| `view_binding` | all-traces | 乗っ取られていない正直な鍵の下で DID に受理された proof は、その DID が、その op・nonce・issuedAt・fields で署名したもの: 同じ鍵を名乗る別の DID にも、別の op にも使い回せない | `viewBytes`（D-w1）、`Verifier.Verify` の 4〜6 |
| `accepted_only_for_audience` | all-traces | 乗っ取られていない正直な鍵の下で検証者に受理された proof は、その検証者の audience に向けて署名されたもの: ある node 向けの proof は別の node では通らない | `viewBytes` と `Verifier.Verify` の 1 の audience の照合（D-w12） |
| `nonce_names_signing` | all-traces | 1 つの nonce の正直な署名は同じ 1 つの署名: `accepted_only_for_audience` が nonce から見つける署名は、`view_binding` が署名者・op・issuedAt・fields から見つける署名と同じ | `wireauth.NewNonce`（proof ごとに新しい nonce。`wireauth.Sign` を呼ぶすべてが使う） |
| `mismatch_spends_no_nonce` | all-traces | 検証者が正直な鍵の nonce を記録するのは、自分の audience に向けて署名された proof だけ: 別の audience 向けの proof は store の前に断られ、nonce を使わない | `Verifier.Verify` の 1 の audience の照合。最後の `NonceStore.Use` より前 |
| `executable_replay_rejected` | exists-trace | 受理された proof を同じ検証者にもう一度出すと断られる | — |
| `once_per_store` | all-traces | 検証者は署名者の nonce を 1 度だけ受理する。store の check-and-set を言い直したもの | 原子的な check-and-set としての `NonceStore.Use`（前提） |
| `nonce_per_signer` | exists-trace | 1 つの検証者が 1 つの nonce を 2 人の署名者について受理する: store の範囲は署名者ごと | `(signerDID, nonce)` を鍵にした `NonceStore`（D-w10） |
| `no_burn` | all-traces | 正直な proof が replay として断られるのは、その proof が先に受理された時か、署名者の鍵が乗っ取られた時だけ: 偽の証明は正しい署名者の nonce を消費しない | `Verifier.Verify` の 8（最後に、成功の時だけ）、署名者ごとの `NonceStore` |
| `replay_across_replicas` | exists-trace | audience が残すもの: 同じ audience を持ち、それぞれ自分の store を持つ 2 つの検証者で 1 つの proof が受理される | —（配備は audience ごとに検証者を 1 つにする） |

`bearerorigins.spthy`:

| lemma | 種類 | 性質 | 実装 |
| --- | --- | --- | --- |
| `executable_presentation` | exists-trace | 名指しの origin の server が、server の侵害なしに bearer を受け取る（到達性） | — |
| `redirect_reachable` | exists-trace | bearer を付けた取得に、server が redirect で答える | — |
| `leak_after_named_compromise` | exists-trace | 名指しの受け手が乗っ取られると、攻撃者は bearer を得うる: その後の秘匿は保証しない | — |
| `delivered_only_to_named` | all-traces | bearer は名指しの origin の server にしか届かない（redirect の先も含めて） | `pipelineconfig.Config.PresentsCredentialTo`、`origin.Confine` |
| `bearer_secrecy` | all-traces | 攻撃者が bearer を知るのは、それを受け取り、その前に乗っ取られた名指しの受け手からだけ | 同上（bearer を付けるすべての client で） |

exists-trace の lemma の多くは、all-traces の lemma が空にならないためにある:
何も受理されない model では安全性は自明に成り立ち、誰も到達できない例外は例外
ではない。2 つは model が閉じない境界を示す: `replay_across_replicas` と
`leak_after_named_compromise`。この 2 つでは、証明はその trace に到達できることを
意味する。

### code では

`vc-store-bearer` を付ける client は、`origin.Confine` で包んだ client で
operator が設定した宛先に向かう（`cmd/pipeline/main.go`、`cmd/pipeline/wiring.go`、
`network/pkg/services/payloadresolver/client` の payload store の client）か、
batch resolver の peer fetcher で、`PresentsCredentialTo` が endpoint を認めた
時だけ bearer と `origin.Confine` を付ける（`internal/netcompose/batchresolver.go`）。

## 負の対照

対照は既定の build の 1 点を変える: 検査を 1 つ外すか、（`RecordBeforeSignature`
は）検査を迂回する経路を 1 つ足す。`check.sh MODEL FLAG` で回し、反証を期待する
lemma は `tamarin/MODEL.expected.tsv` にある。

| model | build | 変えるもの | 反証される lemma |
| --- | --- | --- | --- |
| wireauth | `ViewOmitsSigner` | view が署名者の DID を覆わない（D-w1） | `view_binding`（正直な鍵を名乗る攻撃者の DID） |
| wireauth | `ViewOmitsAudience` | view が audience を覆わない（D-w12） | `accepted_only_for_audience`（ある検証者向けの proof が別の検証者で受理される）、`mismatch_spends_no_nonce` |
| wireauth | `ViewOmitsOp` | view が op を覆わない | `view_binding`、`no_burn`（別の op で先に受理される proof） |
| wireauth | `AudienceFromWire` | 検証者が proof の名指す audience で view を組み直し、自分の audience と比べない | `accepted_only_for_audience`、`mismatch_spends_no_nonce` |
| wireauth | `NoNonceStore` | store の check-and-set が無い: replay の受理を何も止めない | `once_per_store` |
| wireauth | `RecordBeforeSignature` | 署名の検査の前に nonce を記録する経路 | `no_burn`、`mismatch_spends_no_nonce` |
| wireauth | `StoreKeyedByNonce` | store の鍵が nonce だけで、署名者ごとでない（D-w10） | `no_burn`、`nonce_per_signer` |
| wireauth | `SignerNonceFromWire` | 署名者が新しい nonce を引かず、network から受け取る | `nonce_names_signing`、`no_burn`（1 つの nonce で署名した 2 つの proof: 先に受理された方が、もう片方の nonce を使う） |
| wireauth | `RecordBeforeAudience` | proof の名指す audience の view で署名を検査し、nonce を記録してから、別の audience 向けの proof を断る経路 | `mismatch_spends_no_nonce` だけ（検証者が断る proof が nonce を使う） |
| bearerorigins | `PresentToAnyEndpoint` | 名指しの origin の照合が無い | `delivered_only_to_named`、`bearer_secrecy` |
| bearerorigins | `FollowRedirects` | `origin.Confine` が無い: redirect を追う | `delivered_only_to_named`、`bearer_secrecy` |

## 標準 vector

`vectors/` は第三者の test vector を製品自身の code に通す。プロジェクトの試験と code が同じ実装の細部を共有していても、標準からのずれが隠れないようにするため。

| suite | 出所（pin の commit） | 通す口 | 数 |
| --- | --- | --- | --- |
| Wycheproof: Ed25519、ECDSA P-256 SHA-256（`r \|\| s`）、RSA PKCS #1 v1.5 SHA-256（2048・3072・4096 bit） | [C2SP/wycheproof](https://github.com/C2SP/wycheproof) `d17cc89` | `crypto/ed25519`、`crypto/es256`、`crypto/rs256` の `Verifier` | 1,248 vector |
| RFC 8785: 参照実装の input と output の組、Appendix B の数の例 | [cyberphone/json-canonicalization](https://github.com/cyberphone/json-canonicalization) `32a4819`、RFC | `canon/jcs`（`CanonicalizeRFC8785`）、canonicalizer の段 | 6 組、26 個の数 |
| JSON-Schema-Test-Suite、draft 2020-12、必須の試験 | [json-schema-org/JSON-Schema-Test-Suite](https://github.com/json-schema-org/JSON-Schema-Test-Suite) `245a45a` | `schema/local`: `Add` が製品の方針で schema を compile し、`Validate` が data を確かめる | 46 file、385 case、1,300 test |

file は `vectors/testdata/` に手を加えずに置き、出所ごとに license と README を添える。`testdata/SOURCES.tsv` が全 file を SHA-256 で固定し、file が変わるか行なしで足されると試験が落ちる。試験は file を読むだけで、何も実行しない。

**期待。** vector の期待の結果は、その vector 自身のもの（valid か invalid）。製品の契約が別の結果を与えるところだけ、理由と一緒に `vectors/<suite>.expected.tsv` に書く。表の行は vector を回す前に契約から書いた。期待と違う結果、どの vector も使わない行、vector 自身の結果を繰り返す行は、どれも失敗にする。

- **Wycheproof**（`wycheproof.expected.tsv`）: Wycheproof が `acceptable` とする vector は全部行を持ち、断る行は期待する error を名指す（package の error か、検証が false と答えるものは `-`）。小さい位数の Ed25519 の公開鍵は断り（`ed25519.ValidatePublicKey`）、R が小さい位数の点である署名も断る（どちらも `ed25519.ErrSmallOrder`）。混合位数の鍵の下のほかの署名は、標準ライブラリの式が受けるとおりに受ける。試験は、この 21 行を含む Ed25519 の vector すべての結果を、製品を使わずに導き直す: `crypto/ed25519.Verify` と、点が正規の形か・小さい位数かを決める曲線の演算から（標準ライブラリが受ける vector のうち 8 つは、曲線の演算だけが断る）。DigestInfo に NULL の無い RSA の署名は断る（strict な PKCS #1 v1.5）。ほかの vector はすべて自身の結果。
- **RFC 8785**: 例外は無い。canonicalizer は参照実装の全 input に output を byte で一致して与え、Appendix B の有限の値すべてにその直列化を与える。NaN と Infinity は断る。参照実装の input `structures` は大文字小文字だけ違う object の名前を使い、製品の strict な decode はそれを断る（`canon.DuplicateKeyError`）。そのためこの 1 組は canonicalizer の段だけで照合する。strict な decode を通すと、ほかの 5 組は同じ bytes になる。canonicalize の前に admission が断るもの（`canon.AdmitSafeNumbers`。RFC 8785 自身の `1e30` など）は、この段に含まない。W3C の JCS の test vector は `vc` 自身の試験が照合している（`vc/w3c_forkw_internal_test.go`、`vc/rdfc_internal_test.go`）。
- **JSON-Schema-Test-Suite**（`jsonschema.expected.tsv`）: 結果は、製品がそれをどう扱ったか（assertion が成り立つか、落ちるか、どの拒否か）で分ける。どの class にも当たらない error は失敗にする。profile の除外の class は 1 つで、`refused-external-ref`: 自分の外の document を指す schema（suite の `http://localhost:1234` の remote schema）は断る。製品は外部の `$ref` を読まない（22 case、run の前に列挙）。pattern は Unicode の general category を、短い名前か、長い名前・別名で、ECMA-262 の綴りのとおりに書く（`L`、`Letter`、`Nd`、`digit` …）。

  各行は期待する error も名指すので、別の理由の拒否は失敗になる。上限と予算、製品の方言の外の pattern、metaschema が断る schema、decode が断る payload の class は、run の前に 0 件と宣言し、0 件のまま。

## 結果

lemma の状態は 5 つ: **証明**、**反証（期待どおり）**（負の対照）、
**反証（設計の穴）**、**未解決**（探索が終わらない、timeout、model の誤り）、
**未着手**。未解決は証明に数えない。ここに書いた状態で model は merge でき、
次の release までに証明する・弱める・落とすのどれかにする。期待に無い反証は
CI を赤にする。

| model | build | 状態 |
| --- | --- | --- |
| wireauth | 既定 | 12 すべて証明 |
| wireauth | 9 つの対照それぞれ | 上の表の lemma が期待どおり反証、ほかは証明 |
| bearerorigins | 既定 | 5 つすべて証明 |
| bearerorigins | 2 つの対照それぞれ | 上の表の lemma が期待どおり反証、ほかは証明 |
| `NonceEpoch`（TLA+: 受理の窓、再起動の epoch、掃除） | — | 未着手 |

未解決: 無し。

| 標準 vector | 状態 |
| --- | --- |
| Wycheproof（1,248 vector） | すべて期待どおり。表の行は 32 で、すべて `acceptable` の vector |
| RFC 8785（6 組、26 個の数） | すべて期待どおり |
| JSON-Schema-Test-Suite（1,300 test） | すべて期待どおり。表の case は 22 |

## 回し方

```sh
verification/tamarin/check.sh --all-builds              # 全 model、全 build（CI が回すもの）
verification/tamarin/check.sh                           # 全 model、既定の build
verification/tamarin/check.sh wireauth                  # 1 つの model
verification/tamarin/check.sh wireauth ViewOmitsSigner  # 1 つの負の対照
TIMEOUT=120 verification/tamarin/check.sh --all-builds  # lemma ごとの秒数（既定 600）
(cd verification && go test ./...)                      # 標準 vector（CI の job vectors が回すもの）
```

`check.sh` は lemma ごとに別の process で `tamarin-prover` を回し、prover の
summary を読み（反証された lemma でも exit code は 0）、結果を分類し、すべての
lemma が `MODEL.expected.tsv` の名指す結果の時だけ exit 0 にする。時間切れの lemma
は未解決で、反証ではない。`--all-builds` は build を各 `MODEL.expected.tsv` から
読むので、CI は build を 1 つも並べない。

prover を回す前に、`check.sh` は model と期待を照らし、ずれていれば理由を出して
止まる: 期待が build として名指さない `FLAG`（`tamarin-prover` は知らない `-D` を
無視して既定の model を回すため）、build でない model の `#ifdef`、`#ifdef` でない
build、model に無い期待の lemma、`#ifdef` の中の lemma、flag が 1 つでない
`#ifdef`、`verified`・`falsified`・`unresolved` のどれでもない期待の結果。

script は `dplaax.spec` の `formal/tamarin/check.sh` と byte 単位で同じで、`cmp` か
SHA-256 で 2 つのずれが分かる。

道具: Tamarin 1.12.0 と Maude 3.5.1。CI が SHA-256 で pin する版
（[`.github/workflows/formal.yml`](../.github/workflows/formal.yml)）。macOS では
`brew install tamarin-prover/tap/tamarin-prover`（Maude も入る）。

## review

CI は `verification/tamarin/` か workflow が変わった時に model を回す。model か、
model の契約が述べる code（`network/pkg/wireauth`、
`wireauth.Sign` の呼び手と、その audience の出所（`cmd/pipeline/audience.go`、chain manager の subscriber）、node の検証者（`internal/netcompose`）、L2 の proof を検証する handler、`pipelineconfig.Config.PresentsCredentialTo`、
`internal/origin`、`vc-store-bearer` を付ける client）を変える pull request は、
上の契約が code でまだ成り立つかを review する。

model と code が食い違った時、既定の勝者は置かない: 食い違いを裁定し、誤っている
方を直し、結論を記録する。
