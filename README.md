# IapAuther

Google Cloud Identity-Aware Proxy (Cloud IAP) でのさまざまな認証に対応する **.NET 10** 製 CLI ツールです。

- **トークン発行 (`token`)**: OIDC ID トークンや自己署名サービスアカウント JWT を発行して標準出力へ出力 (`curl` 等との連携に最適)
- **headersHelper 用 JSON 出力 (`headers`)**: `Proxy-Authorization` と任意の追加ヘッダ (`-H` / `--header`) を含む JSON オブジェクトを標準出力へ出力 (Claude Code 等の `headersHelper` 向け)
- **MCP Proxy (`mcp-proxy`)**: stdio クライアント (Claude Desktop / Claude Code / Cursor 等) と IAP 保護された HTTP MCP サーバー (Streamable HTTP / Legacy HTTP+SSE) を公式 [MCP C# SDK](https://github.com/modelcontextprotocol/csharp-sdk) (`ModelContextProtocol.Core`) 経由でつなぐブリッジ

## 必要環境

- [.NET 10 SDK / Runtime](https://dotnet.microsoft.com/download/dotnet/10.0)

## ビルド・インストール

### ソースから実行

```sh
dotnet run --project src/IapAuther -- --help
```

### NuGet から dotnet tool としてインストール

```sh
dotnet tool install -g IapAuther
iap-auther --help
```

### ローカルビルドから dotnet tool としてインストール

```sh
dotnet pack src/IapAuther/IapAuther.csproj -c Release -o ./nupkg
dotnet tool install -g IapAuther --add-source ./nupkg
iap-auther --help
```

## 使い方

### 1. トークン発行モード (`token`)

```sh
iap-auther token [options] [UPSTREAM_URL]
```

例:

```sh
# 外部 Application Load Balancer 配下の IAP (カスタム OAuth クライアント)
TOKEN=$(iap-auther token --audience 1234567890-abc.apps.googleusercontent.com)
curl -H "Proxy-Authorization: Bearer ${TOKEN}" https://app.internal.example.com/

# Direct Cloud Run IAP (Google-managed OAuth クライアント → signjwt が必須)
iap-auther token \
  --credentials signjwt \
  --impersonate-service-account mcp-caller@my-project.iam.gserviceaccount.com \
  https://my-svc-xxxx.a.run.app/mcp

# ローカルのサービスアカウント JSON キーを使って自己署名 JWT を発行
iap-auther token \
  --credentials signjwt \
  --credential-file ./sa-key.json \
  --format json \
  https://my-svc-xxxx.a.run.app/mcp
```

`--format` オプション:
- `raw` (デフォルト): JWT トークン本体のみを出力
- `header`: `Proxy-Authorization: Bearer <token>` 形式で出力
- `json`: トークン・audience・有効期限 (`expires_at`)・claims (`subject`, `issuer`, `email`) 等を JSON で出力

---

### 2. `headersHelper` 用 JSON 出力モード (`headers`)

```sh
iap-auther headers [options] [UPSTREAM_URL]
```

`Proxy-Authorization: Bearer <token>` と、`-H` / `--header` で指定した任意の追加ヘッダをまとめた JSON オブジェクトを 1 行で標準出力へ出力します（Claude Code 等の HTTP/WebSocket MCP `headersHelper` からそのまま呼び出せます）。

```sh
# 基本形 ({"Proxy-Authorization":"Bearer ..."} を出力)
iap-auther headers --audience 1234567890-abc.apps.googleusercontent.com

# 追加ヘッダ付き (下流の Authorization を環境変数から渡す例)
iap-auther headers \
  --credentials signjwt \
  --impersonate-service-account mcp-caller@my-project.iam.gserviceaccount.com \
  -H "Authorization: env:DOWNSTREAM_TOKEN" \
  -H "X-Tenant-Id: team-a" \
  https://my-svc-xxxx.a.run.app/mcp
```

Claude Code (`~/.claude.json` 等) の設定例:

```json
{
  "mcpServers": {
    "my-iap-mcp": {
      "type": "http",
      "url": "https://my-svc-xxxx.a.run.app/mcp",
      "headersHelper": "iap-auther headers --credentials signjwt --impersonate-service-account mcp-caller@my-project.iam.gserviceaccount.com -H \"Authorization: env:DOWNSTREAM_TOKEN\" https://my-svc-xxxx.a.run.app/mcp"
    }
  }
}
```

#### Claude Code 等の `headersHelper` で使う場合の注意点

- **`-H` / `--header` による追加ヘッダ指定**: `-H "Name: Value"` を複数回指定でき、値に `env:VAR_NAME` を書くと環境変数から展開します（`Proxy-Authorization` は IAP トークンで自動設定されるため `-H` での上書きはできません）。
- **`stdout` 汚染の防止と `--log-output`**: デフォルト（`--log-output stderr`）ではログ・エラー・OAuth 認証案内はすべて `stderr` に出力され、ブラウザ起動プロセス（`open` / `xdg-open`）の出力も `/dev/null` へ破棄されるため、`stdout` には JSON（`token` ではトークン／JSON）のみが出力されます。切り分け・デバッグ等で `stdout` にもログを出したい場合は `--log-output both`（または `stdout`）を指定してください。
- **タイムアウト対策（OAuth の事前サインイン）**: `headersHelper` には短い実行タイムアウト（Claude Code では約 10 秒）があります。`--credentials oauth`（または `auto` からのフォールバック）を使う場合は、事前にターミナルから一度 `iap-auther headers ...` または `iap-auther token ...` を手動実行してブラウザ認証を完了し、リフレッシュトークンをキャッシュさせてから `headersHelper` を動かしてください（2 回目以降はキャッシュ済みリフレッシュトークンで高速に更新されます）。
- **プロジェクトスコープの環境変数制限**: プロジェクトスコープの `.mcp.json` では、クライアント側のセキュリティ制限により `TOKEN` / `SECRET` / `KEY` / `AUTH` 等を含む環境変数（`IAP_AUTHER_OAUTH_CLIENT_SECRET` や `env:DOWNSTREAM_TOKEN` 等）が `headersHelper` に渡らない場合があります。ラッパースクリプトやユーザースコープ設定を利用するか、トークン更新と 401/302 リトライを内蔵した [`mcp-proxy` モード](#3-mcp-proxy-モード-mcp-proxy) の利用を検討してください。

---

### 3. MCP Proxy モード (`mcp-proxy`)

```sh
iap-auther mcp-proxy [options] <UPSTREAM_URL>
```

stdio ⇄ HTTP (Streamable HTTP / Legacy HTTP+SSE 自動判別) ブリッジとして動作し、リクエストに `Proxy-Authorization: Bearer <token>` を自動付与・自動リフレッシュします。

Claude Desktop 設定例:

```json
{
  "mcpServers": {
    "internal-tools": {
      "command": "iap-auther",
      "args": [
        "mcp-proxy",
        "--audience", "1234567890-abc.apps.googleusercontent.com",
        "https://mcp.internal.example.com/mcp"
      ]
    }
  }
}
```

Direct Cloud Run IAP (Google-managed OAuth クライアント) の場合:

```json
{
  "mcpServers": {
    "cloud-run-mcp": {
      "command": "iap-auther",
      "args": [
        "mcp-proxy",
        "--credentials", "signjwt",
        "--impersonate-service-account", "mcp-caller@my-project.iam.gserviceaccount.com",
        "https://my-mcp-xxxx.a.run.app/mcp"
      ]
    }
  }
}
```

## 対応する認証パターン (`--credentials`)

| モード | トークン種別 | 仕組み / 用途 |
|---|---|---|
| `auto` (デフォルト) | 自動選択 | `--impersonate-service-account` 指定時は `impersonate`。未指定時は `adc` を試し、ADC が `authorized_user` (gcloud ユーザー認証情報) の場合は `oauth` (デスクトップ OAuth) へフォールバック。 |
| `adc` | OIDC ID トークン | Application Default Credentials (SA キー、Workload Identity、GCE メタデータ等) または `--credential-file` から OIDC ID トークンを取得。 |
| `impersonate` | OIDC ID トークン | IAM Credentials API (`generateIdToken`) を呼び出し、指定 SA として OIDC ID トークンを発行 (`roles/iam.serviceAccountTokenCreator` が必要)。 |
| `signjwt` | 自己署名 SA JWT | Direct Cloud Run IAP (Google-managed OAuth クライアント) 向け。`--impersonate-service-account` 指定時は IAM `signJwt` API を使用し、未指定かつ ADC/`--credential-file` が SA キーの場合はローカルの秘密鍵で直接署名 (`RS256`)。 |
| `oauth` | OIDC ID トークン | デスクトップ OAuth 2.0 (PKCE + ローカルループバック `/authorize/` + ブラウザ認証)。リフレッシュトークンは各 OS のクレデンシャルストア（Windows Credential Manager / macOS Keychain / Linux Secret Service over D-Bus）に保存し、利用不可時は従来ファイル（Windows: DPAPI、Linux/macOS: `0600`）へフォールバック（`--token-store` で切替可）。 |

## オプション・環境変数一覧

| フラグ | 環境変数 (`IAP_AUTHER_*` / `IAP_MCP_*`) | デフォルト | 説明 |
|---|---|---|---|
| `-a, --audience` | `IAP_AUTHER_AUDIENCE` / `IAP_MCP_AUDIENCE` | `UPSTREAM_URL` の origin (`signjwt` はエンドポイント URL または `<origin>/*`) | トークンの `aud` |
| `-c, --credentials` | `IAP_AUTHER_CREDENTIALS` / `IAP_MCP_CREDENTIALS` | `auto` | `auto` / `adc` / `impersonate` / `oauth` / `signjwt` |
| `-s, --impersonate-service-account` | `IAP_AUTHER_IMPERSONATE_SA` / `IAP_MCP_IMPERSONATE_SA` | — | 対象サービスアカウントのメールアドレス |
| `--credential-file` | `IAP_AUTHER_CREDENTIAL_FILE` | — | SA JSON キーまたは ADC ファイルのパス |
| `--oauth-client-id` | `IAP_AUTHER_OAUTH_CLIENT_ID` / `IAP_MCP_OAUTH_CLIENT_ID` | — | デスクトップ OAuth クライアント ID |
| `--oauth-client-secret` | `IAP_AUTHER_OAUTH_CLIENT_SECRET` / `IAP_MCP_OAUTH_CLIENT_SECRET` | — | デスクトップ OAuth クライアントシークレット |
| `--token-store` | `IAP_AUTHER_TOKEN_STORE` / `IAP_MCP_TOKEN_STORE` | `auto` | OAuth リフレッシュトークンの保存先 (`auto` / `os` / `file`)。`auto` は OS ストア優先（既存のファイル保存分を自動移行し旧ファイルを削除、OS ストア利用不可時はファイル保存へフォールバック）、`os` は OS ストア必須、`file` は従来ファイル (DPAPI / `0600`) |
| `--no-browser` | — | `false` | ブラウザを自動起動せず認証 URL をログ出力先 (デフォルト `stderr`) に表示 |
| `-l, --log-level` | `IAP_AUTHER_LOG` / `IAP_MCP_LOG` | `warn` | `debug` / `info` / `warn` / `error` |
| `--log-output` | `IAP_AUTHER_LOG_OUTPUT` / `IAP_MCP_LOG_OUTPUT` | `stderr` | ログ・エラー・認証案内の出力先 (`stderr` / `stdout` / `both`)。`stdout` / `both` はデバッグ用途向け (`token` / `headers` / `mcp-proxy` の機械処理用 `stdout` に混ざるため通常利用時は非推奨) |
| `-f, --format` *(token)* | — | `raw` | 出力形式 (`raw` / `header` / `json`) |
| `-H, --header` *(headers)* | — | — | 追加 HTTP ヘッダ (`Name: Value` 形式、複数指定可、`env:VAR_NAME` 参照対応) |
| `--downstream-auth` *(mcp-proxy)* | `IAP_AUTHER_DOWNSTREAM_AUTH` / `IAP_MCP_DOWNSTREAM_AUTH` | — | 上流 `Authorization` ヘッダーに転送する値 (`env:VAR_NAME` 参照対応) |
| `--refresh-margin` *(mcp-proxy)* | `IAP_AUTHER_REFRESH_MARGIN` / `IAP_MCP_REFRESH_MARGIN` | `5m` | 有効期限の指定時間前にトークンを更新 |
| `--timeout` *(mcp-proxy)* | `IAP_AUTHER_TIMEOUT` / `IAP_MCP_TIMEOUT` | `120s` | JSON レスポンスの全体タイムアウト / SSE ストリームのアイドルタイムアウト |
| `--transport` *(mcp-proxy)* | `IAP_AUTHER_TRANSPORT` / `IAP_MCP_TRANSPORT` | `auto` | トランスポート方式 (`auto` / `streamable-http` / `sse`) |

## MCP Proxy の主な機能

- **MCP C# SDK ベースのトランスポートブリッジ**: 公式 `ModelContextProtocol.Core` の `HttpClientTransport` (`AutoDetect` / `StreamableHttp` / `Sse`) とカスタム `TransportBase` を組み合わせ、stdio ⇄ HTTP 間でプロトコル透過な JSON-RPC ブリッジを実行します (`stdout` は JSON-RPC 専用、SDK ログは `stderr` へルーティング)。
- **認証エラー時の自動リトライ**: 401 または `accounts.google.com` への 302 リダイレクトを受信した場合、キャッシュを破棄してトークンを再取得し 1 回だけリトライします。再失敗時は `X-Goog-Iap-Generated-Response` やレスポンス本文を解析し、原因に応じたメッセージを stderr に出力します。
- **透過的なセッション復旧**: Cloud Run の再デプロイ等で上流が `404` (セッション期限切れ) を返した場合、キャッシュ済み `initialize` / `notifications/initialized` を自動再生してセッションを再確立し、元のリクエストをリトライします。
- **SSE ストリーム再開 (`Last-Event-ID`)**: レスポンス中の SSE 切断時に、受信済み `id:` を使って `GET` で途中再開します。
- **サーバー主導通知の受信**: `initialize` 後にスタンドアロン `GET` SSE ストリームを開き、指数バックオフと `Last-Event-ID` で再接続します (`405` の場合は静かに停止)。
- **クリーンシャットダウン**: 終了時に `DELETE` リクエストで MCP セッションを終了します。
- **終了コード**: `0` 正常終了、`1` 設定エラーまたは致命的エラー、`2` 認証ブートストラップ失敗。

## テスト

```sh
dotnet test
```

各 OS（Linux `ubuntu-latest` + GNOME Keyring / Windows `windows-latest` + Credential Manager / macOS `macos-latest` + Keychain）での実ストア結合テストを含むマトリクステストは、[`test-matrix.yml`](.github/workflows/test-matrix.yml) の `workflow_dispatch` から手動実行できます（GitHub Actions 無料枠の節約のため push / PR では自動実行しません）。

## リリース (NuGet Trusted Publishing)

[`publish.yml`](.github/workflows/publish.yml) により、`v*` タグのプッシュ（例: `v0.1.0`）または GitHub Actions の `workflow_dispatch` から `production` Environment 経由の OIDC Trusted Publishing で NuGet.org へ公開されます（タグプッシュ時は GitHub Release も自動作成）。

```sh
git tag v0.1.0
git push origin v0.1.0
```
