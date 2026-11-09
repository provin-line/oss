# canon — 署名スコープの正規化
> 日本語版 — English: [README.md](README.md)

JSON 署名スコープの決定論的なバイト表現と、それを保護する厳格なデコーダー。単一の責務に対し、暗号スイートごとの複数アルゴリズムを提供する。

## このパッケージが存在する理由

**同じ論理ドキュメントに対して 2 つのピアが異なる正規バイトを計算する**ことは partition trap（partition trap）である: 検証が失敗する（あるいはより深刻なことに、明確なエラーなく結果が食い違う）。このパッケージのすべてのルールは、Go 以外の実装（Java・Rust・JS）に対しても含め、この障害モードを防ぐために存在する。

## サブパッケージ

| パス | アルゴリズム | 状態 |
| --- | --- | --- |
| `canon/jcs` | RFC 8785 JSON Canonicalization Scheme（Phase 1 暗号スイート、MUST） | 実装済み |
| `canon/urdna2015` | `eddsa-rdfc-2022` 向け RDF Dataset Canonicalization（URDNA2015）（Phase 2、MAY） | 実装済み — `piprate/json-gold` をオフラインの context allowlist（ネットワークには決して出ない）の背後にラップし、JSON-LD 処理が署名スコープから暗黙に落とすもの（未定義 term・相対 `@id`/`@type` 値・数値メンバー（2^53 切り捨て））はすべて fail-closed で拒否する。入れ子の深さ（object と配列で 10,000 段まで。encoding/json が decode するのと同じ）と、dataset を作る手間（json-gold の node map が、1 つの node の property に集まる値を比べる）と、正規の形の長さ（1 MiB と、文書の 1 byte あたり 32 byte）に上限を置き、blank node の名付けも手間の上限の中で行う（RDFC-1.0 §4.4.3）。限りより深い入れ子の文書と、作るか、書くか、名付けるのに上限を超える dataset は `urdna2015.ErrTooComplex` で拒否する。正規の形が持たない値を 1 つでも持つ文書は拒否する: 値を、文書、展開した形、dataset の 3 か所で数え、数が合うことを確かめる。`@base` を置く context と、1 つの node の property が 1 つの RDF の term を 2 度持つ文書も拒否する（node は 1 度だけ書き、ほかでは `@id` で参照する）。ASCII の英数字と hyphen 以外を含む言語の札と、RDF の collection の語（`rdf:first`、`rdf:rest`、`rdf:nil`）を書いた文書と、list の object の `@list` の横に何かを書いた文書、`@set` や framing の keyword を書いた文書、展開できない項目を持つ list も拒否する（列は `@list` だけで書く。set の値は `@set` なしで書く）。1 つの node の 1 つの property は、異なる値が約 1,460 まで。越える文書は、proof を作る時も確かめる時も `ErrTooComplex` で拒否する。`vc` がこの suite を登録するのは、process が `vc.RegisterEdDSARDFC2022` を呼んだ時だけ。それまでは、`vc` はこの suite の proof を発行も確かめもせず、JSON-LD の処理も走らせない。`vc` の suite は、`@context` に、埋め込む context の IRI だけを受け、文書に書いた context を断る。`Canonicalize` そのものは、文書に書いた context も、上の形の内で読む。正規の N-Quads が 1 対 1 に書けない IRI や literal、RDFC-1.0（Appendix A）と違う形に書く literal も拒否する。断る形と、それを断る確かめは、package の doc に一覧で書いてある。公式 W3C vc-di-eddsa test vector にアンカー |

## 厳守ルール

- **StrictDecoder はプロトコル境界における唯一の JSON デコードパスである**: 重複キー（RFC 8785 §3.2.5）を拒否し、末尾データを拒否し、`json.Number` による数値精度を保持する（2^53 を超える整数は float64 に丸めてはならない）。`make lint` が `scripts/check-decoder-hygiene.sh` でこれを強制する。適用除外には `decoder-hygiene-exempt` コメントが必要。
- JCS の出力は RFC 8785 とバイト単位で一致しなければならない — Go のエンコーダーがデフォルトで違反する U+2028/U+2029 の生 UTF-8 要件も含む。
- URDNA2015 は**オフラインドキュメントローダーのみ**を使用する: JSON-LD コンテキストはプロセス内のアローリスト（埋め込みバイト）から取得し、ネットワークからは取得しない。
- ドキュメントに保持すべき既知の制限: JSON-LD パスは `@json` リテラル整数を 2^53 以上で切り詰める。RDF 暗号スイートを使用する場合、大きな整数は文字列としてエンコードしなければならない。
