# contentaddress — 中身の番地
> 日本語版 — English: [README.md](README.md)

dPLaaX の中身の番地（schema の `contentAddress`）。中身を引く番地で、`sha256:` と、中身の SHA-256 の 64 字の小文字 hex で書く。

`Address` を作れるのは `Of`（bytes の番地）と `Parse`（その 1 つの書き方だけを読み、ほかの大文字・小文字、長さ、前後の空白は断る）だけなので、package `unsafe` を使わない限り、どの `Address` も 1 つの書き方であり、ほかの値から変えて作ることはできない。2 つの番地は、書き方が（つまり SHA-256 の digest が）等しいときに限って等しい（`==`）。`Address` は map の key にもなる。ゼロ値の `Address` は「番地なし」（`IsZero`）。

JSON の文字列としては、1 つの書き方で書き、読む（`MarshalText`、`UnmarshalText`）。ゼロ値は書かない。番地がないこともある欄は pointer にして、ないときは nil にするか、`omitzero` を付ける。
