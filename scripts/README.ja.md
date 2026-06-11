# scripts/ — CI 衛生チェック
> 日本語版 — English: [README.md](README.md)

`make lint` および CI から実行される、リポジトリ固有の lint スクリプト群。

- `check-decoder-hygiene.sh` — プロトコルパス上のすべての JSON デコードが `canon` の厳格なデコーダーを経由することを確認する。直接 `json.Unmarshal` を使う場合は `decoder-hygiene-exempt` コメントが必要。
- `check-canonicalizer-hygiene.sh` — 正規化が `canon` のエントリーポイント経由でのみ行われることを確認する（署名スコープへのアドホックな `json.Marshal` を禁止）。
