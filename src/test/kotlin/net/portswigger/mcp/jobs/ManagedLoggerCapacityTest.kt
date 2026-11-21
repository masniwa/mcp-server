package net.portswigger.mcp.jobs

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.handler.HttpHandler
import io.mockk.*
import net.portswigger.mcp.KtorServerManager
import net.portswigger.mcp.schema.HttpService
import net.portswigger.mcp.tools.LoggerHttpHistory
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.nio.file.Path

class ManagedLoggerCapacityTest {
    @Test fun `multi variant workflow evidence exceeds legacy count without changing byte limit or legacy behavior`() {
        for (enabled in listOf(false,true)) {
            val api=mockk<MontoyaApi>(relaxed=true)
            val nativeHttp=api.http()
            val recorder=slot<HttpHandler>()
            every { nativeHttp.registerHttpHandler(capture(recorder)) } returns mockk(relaxed=true)
            val settings=if(enabled) ManagedSettings(true,"worker-token-".repeat(4),"cph-token-".repeat(4),Path.of("..","temp"),emptySet()) else ManagedSettings(false,null,null,null,emptySet())
            val manager=KtorServerManager(api,settings)
            try {
                val history=recorder.captured as LoggerHttpHistory
                repeat(6000) { i -> history.recordRequest(i,"SCANNER",HttpService("127.0.0.1",18084,false),"http://127.0.0.1:18084/owned","request-$i",null) }
                val status=history.status()
                assertEquals(64L*1024*1024,status.maxBytes)
                assertEquals(if(enabled) 6000 else 5000,status.retainedEntries)
                assertEquals(if(enabled) 0L else 1000L,status.droppedEntries)
                assertEquals(if(enabled) 20000 else 5000,status.maxEntries)
                verify(exactly=0) { nativeHttp.sendRequest(any()) }
            } finally { manager.shutdown() }
        }
    }
}
