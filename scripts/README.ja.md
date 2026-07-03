# scripts/ — CI 衛生チェック
> 日本語版 — English: [README.md](README.md)

リポジトリ固有の lint スクリプト群。`check-*.sh` はすべて `make lint`
（CI の lint エントリーポイント）から実行され、チェックの失敗は target を fail させる:

- `check-decoder-hygiene.sh` — プロトコルパス上のすべての JSON デコードが `canon` の厳格なデコーダーを経由することを確認する。直接 `json.Unmarshal` を使う場合は `decoder-hygiene-exempt` コメントが必要。
- `check-canonicalizer-hygiene.sh` — 正規化が `canon` のエントリーポイント経由でのみ行われることを確認する（署名スコープへのアドホックな `json.Marshal` を禁止）。canon を import するファイルでの `json.Marshal` には `canonicalizer-hygiene-exempt` コメントが必要。
- `check-gofmt.sh` — すべての Go ファイルが gofmt 済みであることを確認する。

適用除外コメントは、検出対象の行・その直前の行・`"encoding/json"` import 行（ファイル全体の除外）のいずれかに置き、その箇所で衛生ルールが問題にならない*理由*を明記する。

チェック以外のスクリプト:

- `sync-spec-vectors.sh` — dplaax conformance vector を byte-exact に vendoring し、`conformance/vectors/dplaax/MANIFEST.sha256` を再生成する（spec 変更の取り込み時に実行。`conformance/README.ja.md` 参照）。
