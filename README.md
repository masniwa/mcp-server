# Burp Suite MCP Server Extension

改修REVIEW版1.4.20では、[configure-runtime.ps1](configure-runtime.ps1)で実際にロードするJARとCPHを指定し、clone先・フォルダー名から独立したruntime参照を確認・設定できます。既定は読取り専用で、設定はBurp停止保守に限定します。get_cph_configは起動時の参照情報とruntimeMatchesを返します。導入・改名時の操作は[INSTALL-WINDOWS.md](INSTALL-WINDOWS.md)を参照してください。稼働中の拡張には自動反映しません。

新規Windowsへの管理配布版の導入と初回能力検証は[INSTALL-WINDOWS.md](INSTALL-WINDOWS.md)を参照してください。配布時の配置名はmcp-server／burp-cphです。開発用runtimeや資格情報は移植せず、公開diagnostic_jobの固定ローカル対象と人間承認で確認・登録します。

この改修版は、Extensionsで`build/libs/burp-mcp-all.jar`を選ぶとインストール先のruntime設定で診断ジョブ管理モードを開始します。従来版と改修版の選択、独立配置したCPH -re、認証情報・runner・保存先は[LOAD.md](LOAD.md)へ集約しています。以下は共通のUpstream導入説明です。

通常の`mcp-server -re`はREVIEWで運用します。診断依頼の形式はRequest IDの指定を維持し、AIが対象別の動的設定案を作成してMCP `diagnostic_job`へ渡します。人間承認・非同期実行・ログ保存・回復の仕様は[実行サービス](diagnosis-runner/README.md)、検証結果と未確認範囲は[testing.md](testing.md)を参照してください。

対応版では、新規execute前に`plan_next`へ現在のexecutionIdとnextTargetsJsonで依頼順の残対象を宣言し、最後の対象も`nextTargetsJson="[]"`を明示します。Scan中はAIが次のnative Macro／Rule／CPHを作成して`diagnostic_draft submit_next`へ提出し、サービスが保存済み適用前baselineで既存コンパイラを自動実行します。未正式化の合格済み案も新revision・新draftIdで修正でき、旧下書きを保持して最新の結合済み合格案だけを正式化します。情報不足・未提出・失敗を合格とせず、次対象への設定反映・送信・Scan開始は現在処理の復元後に通常の人間承認と実通信検証を経て行います。設定を生成する外部LLMは追加していません。操作形式は公開Tool Descriptionを参照してください。

## Overview

Integrate Burp Suite with AI Clients using the Model Context Protocol (MCP).

For more information about the protocol visit: [modelcontextprotocol.io](https://modelcontextprotocol.io/)

## Features

- Connect Burp Suite to AI clients through MCP
- Automatic installation for Claude Desktop
- Comes with packaged Stdio MCP proxy server

## Usage

- Install the extension in Burp Suite
- Configure your Burp MCP server in the extension settings
- Configure your MCP client to use the Burp SSE MCP server or stdio proxy
- Interact with Burp through your client!

## Installation

### Prerequisites

Ensure that the following prerequisites are met before building and installing the extension:

1. **Java**: Java must be installed and available in your system's PATH. You can verify this by running `java --version` in your terminal.
2. **jar Command**: The `jar` command must be executable and available in your system's PATH. You can verify this by running `jar --version` in your terminal. This is required for building and installing the extension.

### Building the Extension

1. **Clone the Repository**: Obtain the source code for the MCP Server Extension.
   ```
   git clone https://github.com/PortSwigger/mcp-server.git
   ```

2. **Navigate to the Project Directory**: Move into the project's root directory.
   ```
   cd mcp-server
   ```

3. **Build the JAR File**: Use Gradle to build the extension.
   ```
   ./gradlew embedProxyJar
   ```

   This command compiles the source code and packages it into a JAR file located in `build/libs/burp-mcp-all.jar`.

### Loading the Extension into Burp Suite

1. **Open Burp Suite**: Launch your Burp Suite application.
2. **Access the Extensions Tab**: Navigate to the `Extensions` tab.
3. **Add the Extension**:
    - Click on `Add`.
    - Set `Extension Type` to `Java`.
    - Click `Select file ...` and choose the JAR file built in the previous step.
    - Click `Next` to load the extension.

Upon successful loading, the MCP Server Extension will be active within Burp Suite.

## Configuration

### Configuring the Extension
Configuration for the extension is done through the Burp Suite UI in the `MCP` tab.
- **Toggle the MCP Server**: The `Enabled` checkbox controls whether the MCP server is active.
- **Enable config editing**: The `Enable tools that can edit your config` checkbox allows the MCP server to expose tools which can edit Burp configuration files.
- **Advanced options**: You can configure the port and host for the MCP server. By default, it listens on `http://127.0.0.1:9876`.

### Claude Desktop Client

To fully utilize the MCP Server Extension with Claude, you need to configure your Claude client settings appropriately.
The extension has an installer which will automatically configure the client settings for you.

1. Currently, Claude Desktop only support STDIO MCP Servers
   for the service it needs.
   This approach isn't ideal for desktop apps like Burp, so instead, Claude will start a proxy server that points to the
   Burp instance,  
   which hosts a web server at a known port (`localhost:9876`).

2. **Configure Claude to use the Burp MCP server**  
   You can do this in one of two ways:

    - **Option 1: Run the installer from the extension**
      This will add the Burp MCP server to the Claude Desktop config.

    - **Option 2: Manually edit the config file**  
      Open the file located at `~/Library/Application Support/Claude/claude_desktop_config.json`,
      and replace or update it with the following:
      ```json
      {
        "mcpServers": {
          "burp": {
            "command": "<path to Java executable packaged with Burp>",
            "args": [
                "-jar",
                "/path/to/mcp/proxy/jar/mcp-proxy-all.jar",
                "--sse-url",
                "<your Burp MCP server URL configured in the extension>"
            ]
          }
        }
      }
      ```

3. **Restart Claude Desktop** - assuming Burp is running with the extension loaded.

## Manual installations
If you want to install the MCP server manually you can either use the extension's SSE server directly or the packaged
Stdio proxy server.

### SSE MCP Server
To use the SSE server directly, provide the configured server URL to your MCP client:
```
http://127.0.0.1:9876
```

### Stdio MCP Proxy Server
The source code for the proxy server can be found here: [MCP Proxy Server](https://github.com/PortSwigger/mcp-proxy)

In order to support MCP Clients which only support Stdio MCP Servers, the extension comes packaged with a proxy server for
passing requests to the SSE MCP server extension.

If you want to use the Stdio proxy server you can use the extension's installer option to extract the proxy server jar.
Once you have the jar you can add the following command and args to your client configuration:
```
/path/to/packaged/burp/java -jar /path/to/proxy/jar/mcp-proxy-all.jar --sse-url http://127.0.0.1:9876
```

If you modify the proxy source, rebuild and copy it into this project before packaging the extension:
```bash
# From mcp-proxy
./gradlew shadowJar
cp build/libs/mcp-proxy-all.jar /path/to/mcp-server/libs/mcp-proxy-all.jar

# From mcp-server
./gradlew embedProxyJar
```

### Creating / modifying tools

Tools are defined in `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`. To define new tools, create a new serializable
data class with the required parameters which will come from the LLM.

The tool name is auto-derived from its parameters data class. A description is also needed for the LLM. You can return
a string or a `List<ContentBlock>` to provide data back to the LLM.

Extend the Paginated interface to add auto-pagination support.

## このコピーの診断ジョブ実装

`diagnosis-contract`、`diagnosis-runner`とBurp側の管理実行境界を追加しています。既存互換モードは維持し、管理モードではジョブ内容に結び付けた人間の承認を必須にします。Macro／Rule／CPHのnative設定と既存のMontoya Scanner callbackを再利用します。

構成・状態・起動設定・制約は[診断ジョブ実行サービス](diagnosis-runner/README.md)、検証方法は[testing.md](testing.md)を参照してください。Burpへの配備・実通信は別承認です。
