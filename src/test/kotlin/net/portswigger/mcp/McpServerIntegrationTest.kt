package net.portswigger.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.ServerSocket
import java.util.concurrent.CopyOnWriteArrayList

class McpServerIntegrationTest {
    private val client = TestSseMcpClient()
    private val api = mockk<MontoyaApi>(relaxed = true)
    private val serverManager = KtorServerManager(api)
    private val testPort = findAvailablePort()
    private val persistedObject = mockk<PersistedObject>()
    private val serverStarted = CompletableDeferred<Unit>()
    private val startupEvents = CopyOnWriteArrayList<String>()
    private var startedAtNanos = 0L

    init {
        every { persistedObject.getBoolean(any()) } returns true
        every { persistedObject.getString(any()) } returns "127.0.0.1"
        every { persistedObject.getInteger("port") } returns testPort
        every { persistedObject.setBoolean(any(), any()) } returns Unit
        every { persistedObject.setString(any(), any()) } returns Unit
        every { persistedObject.setInteger(any(), any()) } returns Unit
    }

    private val mockLogging = mockk<Logging>().apply {
        every { logToError(any<String>()) } returns Unit
        every { logToOutput(any<String>()) } returns Unit
    }

    private val config = McpConfig(persistedObject, mockLogging)

    @BeforeEach
    fun setup() {
        startedAtNanos = System.nanoTime()
        serverManager.start(config) { state ->
            startupEvents.add("${state.javaClass.simpleName}:${(System.nanoTime() - startedAtNanos) / 1_000_000}ms")
            when (state) {
                is ServerState.Running -> serverStarted.complete(Unit)
                is ServerState.Failed -> serverStarted.completeExceptionally(state.exception)
                else -> Unit
            }
        }
        
        runBlocking {
            // This verifies readiness and protocol behavior, not a startup SLA.
            // A cold Netty/JAR class load on the test host was observed to reach
            // Running at 3972ms. Keep a finite startup bound, propagate actual
            // failures immediately, and still require connection/list/ping.
            try {
                withTimeout(10000) { serverStarted.await() }
            } catch (error: Exception) {
                Thread.getAllStackTraces().forEach { (thread, stack) ->
                    if (stack.any { it.className.contains("KtorServerManager") }) {
                        println("Startup worker ${thread.name}:\n" + stack.take(24).joinToString("\n"))
                    }
                }
                throw error
            }
        }
    }

    private fun findAvailablePort(): Int {
        return ServerSocket(0).use { it.localPort }
    }

    @AfterEach
    fun tearDown() {
        runBlocking {
            if (client.isConnected()) {
                client.close()
            }
        }
        serverManager.shutdown()
        println("Startup events: ${startupEvents.joinToString()}")
    }

    @Test
    fun `server should accept connections and list tools`() = runBlocking {
        try {
            client.connectToServer("http://127.0.0.1:${testPort}")
            assertTrue(client.isConnected(), "Client should be connected to server")
            
            val tools = client.listTools()
            assertFalse(tools.isEmpty(), "Server should have registered tools")
            
            val toolNames = tools.map { it.name }
            assertTrue(toolNames.contains("output_project_options"), "Server should have output_project_options tool")
            assertTrue(toolNames.contains("output_user_options"), "Server should have output_user_options tool")
            
            val pingResult = client.ping()
            assertNotNull(pingResult, "Ping should return a result")
        } catch (e: Exception) {
            fail("Connection failed: ${e.message}")
        }
    }
}
