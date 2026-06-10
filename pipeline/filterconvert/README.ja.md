# filterconvert — ステートレスな1:1変換コンポーネント
> 日本語版 — English: [README.md](README.md)

FilterConvert コンポーネント型。**ステートレス性は定義的性質**であり、データベース、プール、キャッシュ、クロスイベント状態を持たない。ステートフルな振る舞いは Origin Source に属する。

## 処理ライフサイクル（1イベント）

```
ingress VC verification (strategy: none | adjacent | full)
  → payload extraction → optional input-schema check
  → ordered steps: filter (JSONata; falsy ⇒ "filtered", drop)
                   converter (JSONata; whole-doc or per-field steps mode)
  → optional output validation against the pinned schema version
  → strict decode (duplicate-key reject, precision preserve)
  → inputHash / outputHash computation (sha256)
  → VC signing (chain-preserving: previousCredential = hash of input VC)
  → observer notification (fire-and-forget) → publish
```

不変条件：隣接するチェーンリンク間で `outputHash[n] == inputHash[n+1]` — 下流ステージはペイロードを再読みすることなくデータフローの連続性を証明できる。

## サブパッケージ

- `filter/` — `Filter` インターフェース（`Apply(ctx, data) (*Result, error)`）；`jsonata/` 実装（起動時に式をプリコンパイル；すべてが truthy であればパス）
- `converter/` — `Converter` インターフェース + サブセット出力バリデータ；`jsonata/` 実装（ドキュメント全体モードとシーケンシャルなフィールド別ステップモード）
- `cmd/` — ランタイムバイナリ（設定ロード、gRPC クライアント接続、トランスポートループ）

## エラーセマンティクス（PoC）

フィルタリングされたイベントはサイレントにドロップ（ログ記録）；エラーが発生したイベントはラウドにドロップ（ログ記録）。リトライもデッドレターキューもなし — デッドレタリングは後でプラグインされるセームとして、トランスポートループに位置する。
