# packages/orgverify — DNS ベース組織検証
> 日本語版 — English: [README.md](README.md)

`did:dplaax` の Owner DID が、その `accountId`（FQDN）として使用されているドメインのオーナーによって承認されているかどうかを、DNS TXT レコードを通じて判定する。

## 仕組み

`_dplaax-org.<orgId>` の TXT レコード:

```
v=dplaax1; did=<full owner DID>; key=sha256:<64 lowercase hex>
```

`key` フィンガープリントは、DID Document のアサーションキーから算出されたフィンガープリントとバイト単位で一致しなければならない。厳格なパースは意図的な設計である: 非正規のエンコーディング（大文字の hex・base64）は正規化せず INVALID として扱う — フィンガープリントの一致はセキュリティ境界である。

## 判定結果

`VERIFIED / LIMITED / UNVERIFIED / INVALID / N-A` — 5 段階。VC の信頼度レベルとは直交する。DNS 到達不能はLIMITED にマップされ、レコードが存在しない場合は UNVERIFIED、レコードが矛盾または不一致の場合は INVALID となる。

3 つのエントリーポイント: `Verify`（判定結果）・`Inspect`（判定なしのベストエフォート観察）・`Diagnose`（生成された TXT レコードを含む修正手順）。
