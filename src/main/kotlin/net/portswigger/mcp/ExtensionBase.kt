package net.portswigger.mcp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import net.portswigger.mcp.config.ConfigUi
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.providers.ClaudeDesktopProvider
import net.portswigger.mcp.providers.ManualProxyInstallerProvider
import net.portswigger.mcp.providers.ProxyJarManager
import net.portswigger.mcp.jobs.ManagedSettings

@Suppress("unused")
class ExtensionBase : BurpExtension {

    override fun initialize(api: MontoyaApi) {
        val selectedJar=java.nio.file.Path.of(api.extension().filename())
        net.portswigger.mcp.security.LocalCphCredentials.useInstallation(selectedJar)
        val managed=ManagedSettings.forExtension(root=net.portswigger.mcp.jobs.InstalledRuntime.rootForJar(selectedJar))
        api.extension().setName(if(managed.quick) "Burp MCP Server -re -q (Quick)" else "Burp MCP Server -re")
        val config = McpConfig(api.persistence().extensionData(), api.logging(),managed.enabled,managed.quick)
        val serverManager = KtorServerManager(api,managed)
        managed.profileFile?.let { api.logging().logToOutput("診断ジョブの管理設定：$it") }
        api.logging().logToOutput(if(managed.enabled) "診断ジョブ管理モードで起動します。" else "互換モードで起動します（環境変数による明示指定）。")

        val proxyJarManager = ProxyJarManager(api.logging())

        val configUi = ConfigUi(
            config = config, providers = listOf(
                ClaudeDesktopProvider(api.logging(), proxyJarManager),
                ManualProxyInstallerProvider(api.logging(), proxyJarManager),
            )
        )

        configUi.onEnabledToggled { enabled ->
            configUi.getConfig()

            if (enabled) {
                serverManager.start(config) { state ->
                    configUi.updateServerState(state)
                }
            } else {
                serverManager.stop { state ->
                    configUi.updateServerState(state)
                }
            }
        }

        api.userInterface().registerSuiteTab(if(managed.quick) "MCP -re -q" else "MCP -re", configUi.component)

        api.extension().registerUnloadingHandler {
            serverManager.shutdown()
            configUi.cleanup()
            config.cleanup()
        }

        if (config.enabled) {
            serverManager.start(config) { state ->
                configUi.updateServerState(state)
            }
        }
    }
}
