package net.portswigger.mcp.jobs

import io.mockk.*
import net.portswigger.mcp.ExtensionBase
import burp.api.montoya.MontoyaApi
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class ExtensionBootstrapTest {
    @TempDir lateinit var root:Path
    @Test fun `Burp selected extension filename determines the installation rather than its classloader code source`() {
        val selected=root.resolve("build/libs/burp-mcp-all.jar");Files.createDirectories(selected.parent);Files.writeString(selected,"")
        val api=mockk<MontoyaApi>(relaxed=true)
        val http=api.http()
        val unloaded=slot<burp.api.montoya.extension.ExtensionUnloadingHandler>()
        every { api.extension().registerUnloadingHandler(capture(unloaded)) } returns mockk(relaxed=true)
        every { api.extension().filename() } returns selected.toString()
        every { api.persistence().extensionData().getBoolean("enabled") } returns false
        ExtensionBase().initialize(api)
        assertTrue(Files.exists(root.resolve("runtime/settings.json")))
        val quick=InstalledRuntime.defaultAuthorizationMode()=="QUICK"
        verify { api.extension().setName(if(quick) "Burp MCP Server -re -q (Quick)" else "Burp MCP Server -re") }
        verify { api.userInterface().registerSuiteTab(if(quick) "MCP -re -q" else "MCP -re",any()) }
        verify { api.logging().logToOutput("診断ジョブ管理モードで起動します。") }
        verify(exactly=0) { http.sendRequest(any<burp.api.montoya.http.message.requests.HttpRequest>()) }
        unloaded.captured.extensionUnloaded()
    }
}
