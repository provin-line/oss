# scripts/ — Lint 衛生チェック
> 日本語版 — English: [README.md](README.md)

リポジトリ固有の lint スクリプト群。`check-*.sh` はすべて `make lint`
（将来 CI を設ける場合もこれが単一のエントリーポイント）から実行され、チェックの失敗は target を fail させる:

- `check-decoder-hygiene.sh` — プロトコルパス上のすべての JSON デコードが `canon` の厳格なデコーダーを経由することを確認する。直接 `json.Unmarshal` を使う場合は `decoder-hygiene-exempt` コメントが必要。`encoding/json` の alias import / dot import はチェックを迂回するため、それ自体を拒否する。
- `check-canonicalizer-hygiene.sh` — 正規化が `canon` のエントリーポイント経由でのみ行われることを確認する（署名スコープへのアドホックな `json.Marshal` を禁止）。canon を import するファイルでの `json.Marshal` / `json.NewEncoder` には `canonicalizer-hygiene-exempt` コメントが必要。alias import の拒否も同様。
- `check-number-hygiene.sh` — JSON の数を倍精度で読む所が、すべて `canon.Float64`（RFC 8259 の文法だけ、正しく丸め、綴りに依らない）を通ることを確認する。ほかの `Float64` の method（`json.Number` のもの。呼ぶ形、method value、method expression のどれでも）や `ParseFloat`（どの import 名の `strconv` でも、`math/big` のものでも）を使う場合は、その文字列が JSON の数でない理由を書いた `number-hygiene-exempt` コメントが必要。`rand.Float64()` と `canon.Float64` への言及は通る。行ごとの文字の照合で、import や型は解決しない。
- `check-rdfc-registration.sh` — 試験のファイルの外で `vc.RegisterEdDSARDFC2022` を参照する所が、`vc/cryptosuite.go` の定義のほかに無いことを確認する。これは process 全体で `eddsa-rdfc-2022` を開くので、呼ぶのは program 自身の `main` か、main package の `init` 関数だけで、この module の package は呼ばない。comment と、文字列・raw 文字列・rune の literal は、行を越えても飛ばす。`//go:linkname` の指示は code として読む。`vc` と `canon/urdna2015` のほかの試験でない package が `canon/urdna2015` か json-gold を import した時も失敗する（JSON-LD の処理は `vc` を通してだけ走る）。生成コードも読む。適用除外は無い。
- `check-gofmt.sh` — 生成コード `gen/` を含むすべての Go ファイルが gofmt 済みであることを確認する。

decoder、canonicalizer、number のチェックは、`gen/`（生成コード）を対象にしない。upstream の library の写しである `internal/jsonschema/` では、decoder のチェックが `loader.go` と `content.go`（schema の package が使わない decode）を対象にせず、`schema/internal/schemadoc` のほかの package がこの写しを import すると失敗する。number のチェックは `kind/kind.go`（誤りの文の整形）を対象にしない。その README を参照。

適用除外コメントは、検出対象の行・その直前の行・`"encoding/json"` import 行（ファイル全体の除外）のいずれかに置き、その箇所で衛生ルールが問題にならない*理由*を明記する。

チェック以外のスクリプト:

- `sync-spec-vectors.sh` — dplaax conformance vector を byte-exact に vendoring し、`conformance/vectors/dplaax/MANIFEST.sha256` を再生成する（spec 変更の取り込み時に実行。`conformance/README.ja.md` 参照）。
