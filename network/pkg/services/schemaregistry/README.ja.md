# schemaregistry — イミュータブルスキーマレジストリ
> 日本語版 — English: [README.md](README.md)

パイプラインデータスキーマの追記専用レジストリ。

## ルール

- **イミュータブル + 追記専用**: 登録済みバージョンは変更されない; 非推奨はリスト取得をフィルタするソフトフラグであり、削除ではない。
- バージョンはコンテンツアドレス指定で自動付与される: `YYYY-MM-DD-{hash16}`（`hash16` は `(format, body, prerelease)` をドメイン分離してエンコードした SHA-256 の先頭 16 hex = 64bit）。ハッシュが prerelease を含むため version は完全な一意キーであり、`prerelease` はリスト/表示用メタデータでありキー次元ではない。
- **設計上 "latest" 解決は存在しない。** パイプラインは正確なバージョンをピンし; すべての VC は `schema` 参照（`name:version`）を埋め込む。このルールは、パイプラインステージ間で暗黙的にバージョンがずれるという障害モードを防ぐために存在する。
- スキーマ本文は最大 1 MiB で、それより長いものは読む前に拒否する。
- スキーマ本文は登録時に compile 検証される（JsonSchema: strict-decode、Draft 2020-12、external `$ref` 拒否）。downstream validator が拒否するスキーマをレジストリが保持しないことを保証する。
- `store/yamlstore/` はルートディレクトリ配下に `{name}/{version}.yaml` のレイアウトでセーフセグメントのパスガード付きで管理する。`cmd/network` はこれをデータディレクトリ配下の `schemas/` をルートとして使う（デプロイ後のレイアウトは `schemas/{name}/{version}.yaml`）。
