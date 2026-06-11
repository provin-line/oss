# orgverify — DNS ベース組織検証
> 日本語版 — English: [README.md](README.md)

`did:dplaax` の Owner DID が、その `accountId`（FQDN）として使用されているドメインのオーナーによって承認されているかどうかを、DNS TXT レコードを通じて判定する。

## 仕組み

`_dplaax-org.<orgId>` の TXT レコード:

```
v=dplaax1; did=<full owner DID>; key=sha256:<64 lowercase hex>
```

`key` フィンガープリントは、DID Document のアサーションキーから算出されたフィンガープリントとバイト単位で一致しなければならない。厳格なパースは意図的な設計である: 非正規のエンコーディング（大文字の hex・base64）は正規化せず INVALID として扱う — フィンガープリントの一致はセキュリティ境界である。

## 判定結果

5 つの endorsement 状態。wire field 名は `endorsement_level`（旧称 `level` から rename）: `EndorsementVerified / EndorsementUnreachable / EndorsementMissing / EndorsementInvalid / EndorsementNA`。DNS 到達不能は Unreachable、レコード不在は Missing、矛盾・不一致は Invalid にマップされる。

Endorsement は三軸直交の信頼モデルの 1 軸であり、DID method の trust tier とも VC の confidence state とも独立。

3 つのエントリーポイント: `Verify`（判定結果）・`Inspect`（判定なしのベストエフォート観察）・`Diagnose`（生成された TXT レコードを含む修正手順）。
