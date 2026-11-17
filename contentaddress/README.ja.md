# contentaddress — 中身の番地
> 日本語版 — English: [README.md](README.md)

dPLaaX の中身の番地（schema の `contentAddress`）。中身を引く番地で、`sha256:` と、中身の SHA-256 の 64 字の小文字 hex で書く。

`Address` を作れるのは `Of`（bytes の番地）、`Hasher` の `Address`（分けて書いた bytes の、同じ番地）と `Parse`（その 1 つの書き方だけを読み、ほかの大文字・小文字、長さ、前後の空白は断る）だけなので、package `unsafe` を使わない限り、ゼロ値以外のどの `Address` も 1 つの書き方であり、ほかの値から変えて作ることはできない。2 つの番地は、書き方が（つまり SHA-256 の digest が）等しいときに限って等しい（`==`）。`Address` は map の key にもなる。ゼロ値の `Address` は「番地なし」（`IsZero`）。

`Hasher` は、stream のように分かれて届く bytes の番地を、全部を持たずに作る。分けた bytes を順に書き（`Write`）、`Address` を求める。それは同じ bytes をまとめて `Of` に渡したときの番地で、求めた後も書き足せる。ゼロ値の `Hasher` はそのまま使える。`Hasher` は copy しない（`go vet` が copy を報告する）。method を複数の goroutine から同時に呼んではならない。

JSON の文字列としては、1 つの書き方で書き、読む（`MarshalText`、`UnmarshalText`）。ゼロ値は書かない。番地がないこともある欄は pointer にして、ないときは nil にするか、`omitzero` を付ける。
