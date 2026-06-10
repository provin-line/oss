# packages/merkle — RFC 6962 Merkle コミットメント
> 日本語版 — English: [README.md](README.md)

`source_root` 向けの Merkle ツリー構築: Origin Source が出力を導出した元となるソース VC の集合に対する、コンパクトで順序非依存なコミットメント。

## 規約

- RFC 6962 ドメイン分離: リーフハッシュ = `SHA-256(0x00 ‖ leaf)`、内部ノード = `SHA-256(0x01 ‖ left ‖ right)` — second-preimage 攻撃（CVE-2012-2459 クラス）を防ぐ。
- リーフはツリー構築前にコンテンツハッシュでソートされる（集合意味論 — コミットメントはソース到着順に依存しない）。
- 奇数個のリーフは複製せず**昇格**させる。
- エンコーディング: multibase + multihash（`f1220<64 hex>`）。デコーダーは `f`（base16）と `b`（base32）プレフィックスを受け入れる。
- リーフバイトは、クレデンシャルの `source_root_canonical` フィールドで指定された正規化器によって生成される（`packages/vc` 参照）。このパッケージ自体は正規化方式を選択しない。
