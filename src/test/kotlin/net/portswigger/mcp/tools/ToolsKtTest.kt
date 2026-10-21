package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine
import burp.api.montoya.collaborator.*
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.ByteArray
import burp.api.montoya.http.Http
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpProtocol
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.utilities.Base64Utils
import burp.api.montoya.utilities.RandomUtils
import burp.api.montoya.utilities.URLUtils
import burp.api.montoya.utilities.Utilities
import io.mockk.*
import java.net.InetAddress
import java.time.ZonedDateTime
import java.util.Optional
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import net.portswigger.mcp.KtorServerManager
import net.portswigger.mcp.ServerState
import net.portswigger.mcp.TestSseMcpClient
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.HttpRequestResponse
import net.portswigger.mcp.schema.toSerializableForm
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.net.ServerSocket
import javax.swing.JTextArea

class ToolsKtTest {

    // >> 20261008 mniwa Verify session-rule container isolation, complete rule identity, compatible layouts, and the user-settings wrapper.
    @Test
    fun `session rule lookup ignores unrelated rules arrays`() = runBlocking {
        every { api.burpSuite().exportProjectOptionsAsJson() } returns """
            {
              "project_options":{"sessions":{"session_handling_rules":{"rules":[]}}},
              "proxy":{
                "intercept_client_requests":{"rules":[{"enabled":true,"match_type":"http_method"}]},
                "intercept_server_responses":{"rules":[{"enabled":false,"match_type":"status_code"}]}
              },
              "rules":[{"description":"unrelated","enabled":true}]
            }
        """.trimIndent()
        val result = Json.parseToJsonElement(client.callTool("get_session_handling_rules", emptyMap()).expectTextContent())
        assertEquals(Json.parseToJsonElement("[]"), result)
    }

    @Test
    fun `session rule lookup preserves same name rules with different actions and scope`() = runBlocking {
        val rules = """
            [
              {"description":"same name","enabled":true,"url_scope":"custom","tools_scope":["Scanner"],"include_in_scope":[{"prefix":"http://localhost/a"}],"actions":[{"type":"run_macro","macro_serial_number":11}]},
              {"description":"same name","enabled":true,"url_scope":"custom","tools_scope":["Scanner"],"include_in_scope":[{"prefix":"http://localhost/a"}],"actions":[{"type":"run_macro","macro_serial_number":12}]},
              {"description":"same name","enabled":true,"url_scope":"custom","tools_scope":["Scanner"],"include_in_scope":[{"prefix":"http://localhost/b"}],"actions":[{"type":"run_macro","macro_serial_number":11}]}
            ]
        """.trimIndent()
        every { api.burpSuite().exportProjectOptionsAsJson() } returns
            """{"project_options":{"sessions":{"session_handling_rules":{"rules":$rules}}}}"""
        val result = Json.parseToJsonElement(client.callTool("get_session_handling_rules", emptyMap()).expectTextContent())
        assertEquals(Json.parseToJsonElement(rules), result)
    }

    @Test
    fun `session rule lookup supports nested flat and mirrored session containers`() = runBlocking {
        val rule = """{"description":"native rule","enabled":true,"actions":[]}"""
        val expected = Json.parseToJsonElement("[$rule]")
        val options = listOf(
            """{"project_options":{"sessions":{"session_handling_rules":{"rules":[$rule]}}}}""",
            """{"sessions":{"session_handling_rules":{"rules":[$rule]}}}""",
            """{"session_handling_rules":{"rules":[$rule]}}""",
            """{"project_options":{"sessions":{"session_handling_rules":[$rule]}}}""",
            """{"sessions":{"session_handling_rules":[$rule]}}""",
            """{"session_handling_rules":[$rule]}""",
            """{"project_options":{"sessions":{"session_handling_rules":{"rules":[$rule]}}},"session_handling_rules":[$rule]}"""
        )
        for (json in options) {
            every { api.burpSuite().exportProjectOptionsAsJson() } returns json
            val result = Json.parseToJsonElement(client.callTool("get_session_handling_rules", emptyMap()).expectTextContent())
            assertEquals(expected, result, json)
        }
    }

    @Test
    fun `user options tool documents the native wrapper and imports only user options`() = runBlocking {
        val description = client.listTools().single { it.name == "set_user_options" }.description!!
        assertTrue(description.contains("'user_options'"))
        assertFalse(description.contains("'project_options'"))
        val json = """{"user_options":{}}"""
        val burpSuite = api.burpSuite()
        every { burpSuite.importUserOptionsFromJson(json) } just runs
        client.callTool("set_user_options", mapOf("json" to json)).expectTextContent("User configuration has been applied")
        verify(exactly = 1) { burpSuite.importUserOptionsFromJson(json) }
        verify(exactly = 0) { burpSuite.importProjectOptionsFromJson(any()) }
    }
    // << mniwa

    // >> 20261014 mniwa Test native Proxy IDs and Logger namespaces through real MCP dispatch with independent read permissions.
    @Test
    fun `direct Proxy ID lookup ignores row position and preserves the selected wire pair`() = runBlocking {
        val proxy = api.proxy()
        val http = api.http()
        val first = mockk<ProxyHttpRequestResponse>(relaxed = true)
        val target = mockk<ProxyHttpRequestResponse>(relaxed = true)
        every { first.id() } returns 7
        every { target.id() } returns 42
        every { proxy.history() } returns listOf(target, first)
        val request = mockk<HttpRequest>(relaxed = true)
        every { target.finalRequest() } returns request
        every { request.toString() } returns "GET /wire HTTP/1.1"
        every { request.url() } returns "http://localhost:3000/wire"
        every { request.httpService().host() } returns "localhost"
        every { request.httpService().port() } returns 3000
        every { request.httpService().secure() } returns false
        every { target.time() } returns ZonedDateTime.parse("2026-10-14T00:00:00Z")
        every { target.hasResponse() } returns true
        every { target.originalResponse().toString() } returns "HTTP/1.1 200 OK"
        val result = Json.parseToJsonElement(client.callTool("get_proxy_http_request_by_id", mapOf("requestId" to 42)).expectTextContent()).jsonObject
        assertEquals("FOUND", result["status"]!!.jsonPrimitive.content)
        assertEquals("GET /wire HTTP/1.1", result["proxy"]!!.jsonObject["request"]!!.jsonPrimitive.content)
        assertEquals("HTTP/1.1 200 OK", result["proxy"]!!.jsonObject["response"]!!.jsonPrimitive.content)
        every { target.hasResponse() } returns false
        val pending = Json.parseToJsonElement(client.callTool("get_proxy_http_request_by_id", mapOf("requestId" to 42)).expectTextContent()).jsonObject
        assertEquals("NO_RESPONSE_OBSERVED", pending["proxy"]!!.jsonObject["responseState"]!!.jsonPrimitive.content)
        assertEquals("NOT_FOUND", Json.parseToJsonElement(client.callTool("get_proxy_http_request_by_id", mapOf("requestId" to 0)).expectTextContent()).jsonObject["status"]!!.jsonPrimitive.content)
        every { proxy.history() } returns listOf(target, target)
        assertEquals("AMBIGUOUS", Json.parseToJsonElement(client.callTool("get_proxy_http_request_by_id", mapOf("requestId" to 42)).expectTextContent()).jsonObject["status"]!!.jsonPrimitive.content)
        verify(exactly = 0) { http.sendRequest(any<HttpRequest>()) }
    }

    @Test
    fun `direct Logger ID lookup defaults to unsupported UI rather than returning an equal capture ID`() = runBlocking {
        val http = api.http()
        val handler = slot<burp.api.montoya.http.handler.HttpHandler>()
        verify { http.registerHttpHandler(capture(handler)) }
        val history = handler.captured as LoggerHttpHistory
        history.recordRequest(42, "REPEATER", net.portswigger.mcp.schema.HttpService("localhost", 3000, false), "http://localhost:3000/test", "request-42", null)
        val unsupported = Json.parseToJsonElement(client.callTool("get_logger_http_request_by_id", mapOf("requestId" to 1)).expectTextContent()).jsonObject
        assertEquals("UNSUPPORTED_UI_ID", unsupported["status"]!!.jsonPrimitive.content)
        val found = Json.parseToJsonElement(client.callTool("get_logger_http_request_by_id", mapOf("requestId" to 42, "idType" to "HTTP_MESSAGE_ID", "captureId" to history.status().captureId)).expectTextContent()).jsonObject
        assertEquals("FOUND", found["status"]!!.jsonPrimitive.content)
        assertEquals("request-42", found["logger"]!!.jsonObject["request"]!!.jsonPrimitive.content)
        assertTrue(client.callTool("get_logger_http_request_by_id", mapOf("requestId" to 1, "idType" to "MCP_CAPTURE_ID")).expectTextContent().startsWith("Error:"))
        verify(exactly = 0) { http.sendRequest(any<HttpRequest>()) }
    }

    @Test
    fun `direct ID tools preserve independent history access denial`() = runBlocking {
        mockkObject(config)
        every { config.requireDataAccessApproval } returns true
        every { config.alwaysAllowHttpHistory } returns true
        every { config.alwaysAllowLoggerHistory } returns false
        val previous = net.portswigger.mcp.security.DataAccessSecurity.approvalHandler
        val approval = mockk<net.portswigger.mcp.security.DataAccessApprovalHandler>()
        coEvery { approval.requestDataAccess(any(), any()) } returns false
        net.portswigger.mcp.security.DataAccessSecurity.approvalHandler = approval
        try {
            val denied = Json.parseToJsonElement(client.callTool("get_logger_http_request_by_id", mapOf("requestId" to 1)).expectTextContent()).jsonObject
            assertEquals("ACCESS_DENIED", denied["status"]!!.jsonPrimitive.content)
            coVerify(exactly = 1) { approval.requestDataAccess(net.portswigger.mcp.security.DataAccessType.LOGGER_HISTORY, config) }
            every { config.alwaysAllowHttpHistory } returns false
            val proxyDenied = Json.parseToJsonElement(client.callTool("get_proxy_http_request_by_id", mapOf("requestId" to 1)).expectTextContent()).jsonObject
            assertEquals("ACCESS_DENIED", proxyDenied["status"]!!.jsonPrimitive.content)
        } finally { net.portswigger.mcp.security.DataAccessSecurity.approvalHandler = previous; unmockkObject(config) }
    }
    // << mniwa

    // >> 20261009 mniwa Exercise Logger pagination and filtering through MCP using the registered HTTP handler.
    @Test
    fun `logger tools expose cross tool metadata and apply filtering before pagination`() = runBlocking {
        val handler = slot<burp.api.montoya.http.handler.HttpHandler>()
        val http = api.http()
        verify { http.registerHttpHandler(capture(handler)) }
        val history = handler.captured as LoggerHttpHistory
        val service = net.portswigger.mcp.schema.HttpService("localhost", 3000, false)
        history.recordRequest(20, "PROXY", service, "http://localhost:3000/a", "GET /a HTTP/1.1\r\nHost: localhost:3000\r\n\r\n", null)
        history.recordRequest(21, "SCANNER", service, "http://localhost:3000/b", "POST /b HTTP/1.1\r\nHost: localhost:3000\r\n\r\nbody", null)
        history.recordResponse(21, "SCANNER", service, "http://localhost:3000/b", "POST /b HTTP/1.1\r\nHost: localhost:3000\r\n\r\nbody", "HTTP/1.1 200 OK\r\n\r\nsaved-result", null)
        val first = Json.parseToJsonElement(client.callTool("get_logger_http_history", mapOf("count" to 1, "offset" to 0)).expectTextContent()).jsonObject
        assertEquals("PROXY", first["tool"]!!.jsonPrimitive.content)
        val filtered = Json.parseToJsonElement(client.callTool("get_logger_http_history_regex", mapOf("regex" to "saved-result", "count" to 1, "offset" to 0)).expectTextContent()).jsonObject
        assertEquals("SCANNER", filtered["tool"]!!.jsonPrimitive.content)
        assertEquals("RESPONSE_RECEIVED", filtered["responseState"]!!.jsonPrimitive.content)
        assertEquals("Reached end of items", client.callTool("get_logger_http_history_regex", mapOf("regex" to "SCANNER", "count" to 1, "offset" to 1)).expectTextContent())
        assertTrue(client.callTool("get_logger_http_history", mapOf("count" to 0, "offset" to 0)).expectTextContent().startsWith("Error:"))
        assertTrue(client.callTool("get_logger_http_history_regex", mapOf("regex" to "[", "count" to 1, "offset" to 0)).expectTextContent().startsWith("Error:"))
        val status = Json.parseToJsonElement(client.callTool("get_logger_history_status", emptyMap()).expectTextContent()).jsonObject
        assertEquals("MCP_HTTP_HANDLER", status["source"]!!.jsonPrimitive.content)
        verify(exactly = 0) { http.sendRequest(any<HttpRequest>()) }
    }
    // << mniwa

    @Test
    fun `cached CPH configuration carries extraction and source tab without a second fetch`() = runBlocking {
        val regex = "\"id\"\\s*:\\s*(?P<id>\\d+)"
        val text = client.callTool("generate_cph_import_config", mapOf(
            "tabName" to "cleanup", "enabled" to true, "dynamic" to true,
            "extractMode" to "cached", "modifyType" to "requests",
            "issuerHost" to "localhost", "issuerPort" to 3000, "issuerHttps" to false,
            "singleRequest" to "GET /datainfo HTTP/1.1\r\nHost: localhost:3000\r\n\r\n",
            "singleResponse" to "HTTP/1.1 200 OK\r\n\r\n{\"id\":3}",
            "singleExtractExpression" to regex, "singleExtractExpressionIsRegex" to true,
            "modifyScopeExpression" to "cphtarget:cleanup", "modifyScopeExpressionIsRegex" to false,
            "matchExpression" to "{{cleanup_id}}", "matchExpressionIsRegex" to false,
            "replacementExpression" to "\\g<id>", "replacementExpressionIsRegex" to true,
            "includeOptions" to true, "cachedSelection" to "info_cache"
        )).expectTextContent()
        val root = Json.parseToJsonElement(text).jsonObject
        val handler = root.getValue("cleanup").jsonObject
        assertEquals("2", handler.getValue("extract_choice_index").jsonPrimitive.content)
        assertEquals("info_cache", handler.getValue("cached_selection").jsonPrimitive.content)
        val extraction = handler.getValue("cached_expression") as kotlinx.serialization.json.JsonArray
        assertEquals("true", extraction[0].jsonPrimitive.content)
        assertEquals(regex, extraction[1].jsonPrimitive.content)
        val options = root.values.map { it.jsonObject }.single { "chkbox_scanner" in it }
        assertEquals("true", options.getValue("chkbox_scanner").jsonPrimitive.content)
        assertEquals("false", options.getValue("chkbox_proxy").jsonPrimitive.content)
    }
    
    @Test
    fun `static CPH request correlation uses match groups without an extraction request`() = runBlocking {
        val args = mapOf(
            "tabName" to "local_headers", "dynamic" to false,
            "issuerHost" to "localhost", "issuerPort" to 3000,
            "modifyScopeExpression" to "cphtarget:local_headers",
            "matchExpression" to "(Header: )(value)", "matchExpressionIsRegex" to true,
            "replacementExpression" to "\\g<1>\\g<2>", "singleExtractExpression" to "",
            "includeOptions" to false
        )
        val handler = Json.parseToJsonElement(client.callTool("generate_cph_import_config", args).expectTextContent())
            .jsonObject.getValue("local_headers").jsonObject
        assertEquals("false", handler.getValue("dynamic_checkbox").jsonPrimitive.content)
        assertEquals("", handler.getValue("single_request").jsonPrimitive.content)
        assertEquals("\\g<1>\\g<2>", (handler.getValue("static_expression") as kotlinx.serialization.json.JsonArray)[1].jsonPrimitive.content)
        assertTrue(client.callTool("generate_cph_import_config", args + ("dynamic" to true)).expectTextContent().startsWith("Error:"))
    }

    private val client = TestSseMcpClient()
    private val api = mockk<MontoyaApi>(relaxed = true)
    private val serverManager = KtorServerManager(api)
    private val testPort = findAvailablePort()
    private var serverStarted = false
    private val config: McpConfig
    private val mockHeaders = mutableListOf<HttpHeader>()
    private val capturedRequest = slot<HttpRequest>()

    init {
        val persistedObject = mockk<PersistedObject>().apply {
            every { getBoolean("enabled") } returns true
            every { getBoolean("configEditingTooling") } returns true
            every { getBoolean("requireHttpRequestApproval") } returns false
            every { getBoolean("requireDataAccessApproval") } returns false
            // >> 20261008 mniwa Supply the default credential-filter setting for configuration readback tests.
            every { getBoolean("filterConfigCredentials") } returns true
            // << mniwa
            every { getBoolean("_alwaysAllowHttpHistory") } returns false
            every { getBoolean("_alwaysAllowWebSocketHistory") } returns false
            every { getBoolean("_alwaysAllowOrganizer") } returns false
            every { getString("host") } returns "127.0.0.1"
            every { getString("_autoApproveTargets") } returns ""
            every { getInteger("port") } returns testPort
            every { setBoolean(any(), any()) } returns Unit
            every { setString(any(), any()) } returns Unit
            every { setInteger(any(), any()) } returns Unit
        }
        val mockLogging = mockk<Logging>().apply {
            every { logToError(any<String>()) } returns Unit
            every { logToOutput(any<String>()) } returns Unit
        }

        config = McpConfig(persistedObject, mockLogging)
        
        mockkStatic(HttpHeader::class)
        mockkStatic(burp.api.montoya.http.HttpService::class)
        mockkStatic(HttpRequest::class)
    }

    private fun CallToolResult?.expectTextContent(
        expected: String? = null,
    ): String {
        assertNotNull(this, "Tool result cannot be null")
        val result = this!!

        val content = result.content
        assertNotNull(content, "Tool result content cannot be null")

        val nonNullContent = content
        assertEquals(1, nonNullContent.size, "Expected exactly one content element")

        val textContent = nonNullContent.firstOrNull() as? TextContent
        assertNotNull(textContent, "Expected content to be TextContent")

        val text = textContent!!.text
        assertNotNull(text, "Text content cannot be null")

        if (expected != null) {
            assertEquals(expected, text, "Text content doesn't match expected value")
        }

        return text!!
    }

    private fun setupHttpHeaderMocks() {
        every { HttpHeader.httpHeader(any<String>(), any<String>()) } answers {
            val name = firstArg<String>()
            val value = secondArg<String>()
            mockk<HttpHeader>().also {
                every { it.name() } returns name
                every { it.value() } returns value
                mockHeaders.add(it)
            }
        }

        every { burp.api.montoya.http.HttpService.httpService(any(), any(), any()) } answers {
            val host = firstArg<String>()
            val port = secondArg<Int>()
            val secure = thirdArg<Boolean>()
            mockk<burp.api.montoya.http.HttpService>().also {
                every { it.host() } returns host
                every { it.port() } returns port
                every { it.secure() } returns secure
            }
        }
    }
    
    @BeforeEach
    fun setup() {
        setupHttpHeaderMocks()

        serverManager.start(config) { state ->
            if (state is ServerState.Running) serverStarted = true
        }

        runBlocking {
            var attempts = 0
            // >> 20261014 mniwa Allow ten seconds for the real test server to start under concurrent Burp load without weakening assertions.
            while (!serverStarted && attempts < 100) {
                delay(100)
                attempts++
            }
            // << mniwa
            if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")

            client.connectToServer("http://127.0.0.1:${testPort}")
            assertNotNull(client.ping(), "Ping should return a result")
        }
    }

    private fun findAvailablePort() = ServerSocket(0).use { it.localPort }

    @AfterEach
    fun tearDown() {
        runBlocking { if (client.isConnected()) client.close() }
        serverManager.stop {}
    }

    @Nested
    inner class HttpToolsTests {
        @Test
        fun `http1 line endings should be normalized`() {
            val httpService = mockk<Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val contentSlot = slot<String>()

            every { HttpRequest.httpRequest(any(), capture(contentSlot)) } answers {
                val content = secondArg<String>()
                mockk<HttpRequest>().also {
                    every { it.toString() } returns content
                }
            }
            every { api.http() } returns httpService
            every { httpResponse.toString() } returns "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nResponse body"
            every { httpService.sendRequest(capture(capturedRequest)) } returns httpResponse

            runBlocking {
                val result = client.callTool(
                    "send_http1_request", mapOf(
                        "content" to "GET /foo HTTP/1.1\nHost: example.com\n\n",
                        "targetHostname" to "example.com",
                        "targetPort" to 80,
                        "usesHttps" to false
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                assertFalse(text.contains("Error"), 
                    "Expected success response but got error: $text")
            }

            verify(exactly = 1) { httpService.sendRequest(any<HttpRequest>()) }
            assertEquals("GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n", capturedRequest.captured.toString(), "Request body should match")
        }

        @Test
        fun `http1 request should handle no response`() {
            val httpService = mockk<Http>()
            val contentSlot = slot<String>()

            every { HttpRequest.httpRequest(any(), capture(contentSlot)) } answers {
                val content = secondArg<String>()
                mockk<HttpRequest>().also {
                    every { it.toString() } returns content
                }
            }
            every { api.http() } returns httpService
            every { httpService.sendRequest(any()) } returns null

            runBlocking {
                val result = client.callTool(
                    "send_http1_request", mapOf(
                        "content" to "GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
                        "targetHostname" to "example.com",
                        "targetPort" to 80,
                        "usesHttps" to false
                    )
                )

                delay(100)
                result.expectTextContent("<no response>")
            }
        }

        @Test
        fun `http2 request should be formatted properly`() {
            val httpService = mockk<Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val httpRequest = mockk<HttpRequest>()
            val requestSlot = slot<HttpRequest>()
            val headersSlot = slot<List<HttpHeader>>()
            val bodySlot = slot<String>()

            every { HttpRequest.http2Request(any(), capture(headersSlot), capture(bodySlot)) } returns httpRequest
            every { httpResponse.toString() } returns "HTTP/2 200 OK\r\nContent-Type: text/plain\r\n\r\nResponse body"
            every { api.http() } returns httpService
            every { httpService.sendRequest(capture(requestSlot), HttpMode.HTTP_2) } returns httpResponse

            val pseudoHeaders = mapOf(
                "authority" to "example.com", "scheme" to "https", "method" to "GET", ":path" to "/test"
            )
            val headers = mapOf(
                "User-Agent" to "Test Agent", "Accept" to "*/*"
            )
            val requestBody = "Test body"

            runBlocking {
                val result = client.callTool(
                    "send_http2_request", mapOf(
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(headers),
                        "requestBody" to requestBody,
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                assertFalse(text.contains("Error"), 
                    "Expected success response but got error: $text")
            }

            verify(exactly = 1) { HttpRequest.http2Request(any(), any(), any<String>()) }
            
            assertEquals("Test body", bodySlot.captured, "Request body should match")
            
            val pseudoHeaderList = headersSlot.captured.filter { it.name().startsWith(":") }
            val normalHeaderList = headersSlot.captured.filter { !it.name().startsWith(":") }
            
            assertTrue(pseudoHeaderList.any { it.name() == ":scheme" && it.value() == "https" })
            assertTrue(pseudoHeaderList.any { it.name() == ":method" && it.value() == "GET" })
            assertTrue(pseudoHeaderList.any { it.name() == ":path" && it.value() == "/test" })
            assertTrue(pseudoHeaderList.any { it.name() == ":authority" && it.value() == "example.com" })
            
            assertTrue(normalHeaderList.any { it.name() == "user-agent" && it.value() == "Test Agent" })
            assertTrue(normalHeaderList.any { it.name() == "accept" && it.value() == "*/*" })
        }
        
        @Test
        fun `http2 request should handle null response`() {
            val httpService = mockk<Http>()
            val httpRequest = mockk<HttpRequest>()

            every { HttpRequest.http2Request(any(), any(), any<String>()) } returns httpRequest
            every { api.http() } returns httpService
            every { httpService.sendRequest(any(), HttpMode.HTTP_2) } returns null

            val pseudoHeaders = mapOf("method" to "GET", "path" to "/test")
            val headers = mapOf("User-Agent" to "Test Agent")

            runBlocking {
                val result = client.callTool(
                    "send_http2_request", mapOf(
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(headers),
                        "requestBody" to "",
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )

                delay(100)
                result.expectTextContent("<no response>")
            }
        }
        
        @Test
        fun `http2 pseudo headers should be ordered correctly`() {
            val httpService = mockk<Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val httpRequest = mockk<HttpRequest>()
            val headersSlot = slot<List<HttpHeader>>()

            every { HttpRequest.http2Request(any(), capture(headersSlot), any<String>()) } returns httpRequest
            every { httpResponse.toString() } returns "HTTP/2 200 OK"
            every { api.http() } returns httpService
            every { httpService.sendRequest(any(), HttpMode.HTTP_2) } returns httpResponse

            val pseudoHeaders = mapOf(
                "path" to "/test",
                ":authority" to "example.com", 
                "method" to "GET",
                "scheme" to "https"
            )

            runBlocking {
                val result = client.callTool(
                    "send_http2_request", mapOf(
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(emptyMap<String, String>()),
                        "requestBody" to "",
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )
                
                delay(100)
                assertNotNull(result)
            }
            
            val pseudoHeaderNames = headersSlot.captured
                .filter { it.name().startsWith(":") }
                .map { it.name() }
            
            val expectedOrder = listOf(":scheme", ":method", ":path", ":authority")
            for (i in 0 until minOf(expectedOrder.size, pseudoHeaderNames.size)) {
                assertEquals(expectedOrder[i], pseudoHeaderNames[i],
                    "Pseudo headers should follow the order: scheme, method, path, authority")
            }
        }

        @Test
        fun `create repeater tab http2 should build http2 request`() {
            val repeater = mockk<burp.api.montoya.repeater.Repeater>(relaxed = true)
            val httpRequest = mockk<HttpRequest>()
            val headersSlot = slot<List<HttpHeader>>()
            val bodySlot = slot<String>()

            every { HttpRequest.http2Request(any(), capture(headersSlot), capture(bodySlot)) } returns httpRequest
            every { api.repeater() } returns repeater

            val pseudoHeaders = mapOf(
                "method" to "POST", "path" to "/api/x", "authority" to "example.com", "scheme" to "https"
            )
            val headers = mapOf("Content-Type" to "application/json")
            val requestBody = "{\"k\":\"v\"}"

            runBlocking {
                val result = client.callTool(
                    "create_repeater_tab_http2", mapOf(
                        "tabName" to "h2-tab",
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(headers),
                        "requestBody" to requestBody,
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )

                delay(100)
                assertNotNull(result)
            }

            verify(exactly = 1) { repeater.sendToRepeater(httpRequest, "h2-tab") }
            assertEquals("{\"k\":\"v\"}", bodySlot.captured, "Request body should be passed through unchanged")

            val pseudoHeaderNames = headersSlot.captured.filter { it.name().startsWith(":") }.map { it.name() }
            assertEquals(listOf(":scheme", ":method", ":path", ":authority"), pseudoHeaderNames)
            assertTrue(headersSlot.captured.any { it.name() == "content-type" && it.value() == "application/json" })
        }
    }

    @Nested
    inner class UtilityToolsTests {
        @Test
        fun `url encode should work properly`() {
            val urlUtils = mockk<URLUtils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.urlUtils() } returns urlUtils
            every { urlUtils.encode(any<String>()) } returns "test+string+with+spaces"
            
            runBlocking {
                val result = client.callTool(
                    "url_encode", mapOf(
                        "content" to "test string with spaces"
                    )
                )
                
                delay(100)
                result.expectTextContent("test+string+with+spaces")
            }
            
            verify(exactly = 1) { urlUtils.encode(any<String>()) }
        }
        
        @Test
        fun `url decode should work properly`() {
            val urlUtils = mockk<URLUtils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.urlUtils() } returns urlUtils
            every { urlUtils.decode(any<String>()) } returns "test string with spaces"
            
            runBlocking {
                val result = client.callTool(
                    "url_decode", mapOf(
                        "content" to "test+string+with+spaces"
                    )
                )
                
                delay(100)
                result.expectTextContent("test string with spaces")
            }
            
            verify(exactly = 1) { urlUtils.decode(any<String>()) }
        }
        
        @Test
        fun `base64 encode should work properly`() {
            val base64Utils = mockk<Base64Utils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.base64Utils() } returns base64Utils
            every { base64Utils.encodeToString(any<String>()) } returns "dGVzdCBzdHJpbmc="
            
            runBlocking {
                val result = client.callTool(
                    "base64_encode", mapOf(
                        "content" to "test string"
                    )
                )
                
                delay(100)
                result.expectTextContent("dGVzdCBzdHJpbmc=")
            }
            
            verify(exactly = 1) { base64Utils.encodeToString(any<String>()) }
        }
        
        @Test
        fun `base64 decode should work properly`() {
            val base64Utils = mockk<Base64Utils>()
            val utilities = mockk<Utilities>()
            val burpByteArray = mockk<ByteArray>()
            
            every { api.utilities() } returns utilities
            every { utilities.base64Utils() } returns base64Utils
            every { base64Utils.decode(any<String>()) } returns burpByteArray
            every { burpByteArray.toString() } returns "test string"
            
            runBlocking {
                val result = client.callTool(
                    "base64_decode", mapOf(
                        "content" to "dGVzdCBzdHJpbmc="
                    )
                )
                
                delay(100)
                result.expectTextContent("test string")
            }
            
            verify(exactly = 1) { base64Utils.decode(any<String>()) }
        }

        // >> 20261008 mniwa Verify explicit UTF-8 byte dispatch, Unicode round trips, legacy byte strings, and invalid charset rejection.
        @Test
        fun `base64 UTF-8 mode preserves Japanese emoji and ASCII text`() = runBlocking {
            val base64Utils = mockk<Base64Utils>()
            val utilities = mockk<Utilities>()
            every { api.utilities() } returns utilities
            every { utilities.base64Utils() } returns base64Utils
            mockkStatic(ByteArray::class)
            try {
                every { base64Utils.encodeToString(any<ByteArray>()) } answers {
                    java.util.Base64.getEncoder().encodeToString(firstArg<ByteArray>().getBytes())
                }
                every { base64Utils.decode(any<ByteArray>()) } answers {
                    val raw = java.util.Base64.getDecoder().decode(firstArg<ByteArray>().getBytes())
                    mockk<ByteArray>().also { bytes -> every { bytes.getBytes() } returns raw }
                }
                for (content in listOf("本日の接続担当は、蝶ネクタイのペンギンです。", "ペンギン🐧とお寿司🍣", "test string")) {
                    val raw = content.toByteArray(Charsets.UTF_8)
                    val expected = java.util.Base64.getEncoder().encodeToString(raw)
                    val sourceBytes = mockk<ByteArray>()
                    val encodedBytes = mockk<ByteArray>()
                    every { sourceBytes.getBytes() } returns raw
                    every { encodedBytes.getBytes() } returns expected.toByteArray(Charsets.UTF_8)
                    every { ByteArray.byteArray(*raw) } returns sourceBytes
                    every { ByteArray.byteArray(*expected.toByteArray(Charsets.UTF_8)) } returns encodedBytes
                    val encoded = client.callTool("base64_encode", mapOf("content" to content, "charset" to "UTF-8")).expectTextContent()
                    assertEquals(expected, encoded)
                    val decoded = client.callTool("base64_decode", mapOf("content" to encoded, "charset" to "utf-8")).expectTextContent()
                    assertEquals(content, decoded)
                }
                verify(exactly = 3) { base64Utils.encodeToString(any<ByteArray>()) }
                verify(exactly = 3) { base64Utils.decode(any<ByteArray>()) }
                verify(exactly = 0) { base64Utils.encodeToString(any<String>()) }
                verify(exactly = 0) { base64Utils.decode(any<String>()) }
                for (name in listOf("base64_encode", "base64_decode")) {
                    val description = client.listTools().single { it.name == name }.description!!
                    assertTrue(description.contains("UTF-8"))
                    assertTrue(description.contains("Omit charset"))
                }
            } finally {
                unmockkStatic(ByteArray::class)
            }
        }

        @Test
        fun `base64 default mode preserves Montoya byte string behavior`() = runBlocking {
            val base64Utils = mockk<Base64Utils>()
            val utilities = mockk<Utilities>()
            val bytes = mockk<ByteArray>()
            val content = "é\u0000"
            every { api.utilities() } returns utilities
            every { utilities.base64Utils() } returns base64Utils
            every { base64Utils.encodeToString(content) } returns "6QA="
            every { base64Utils.decode("6QA=") } returns bytes
            every { bytes.toString() } returns content
            client.callTool("base64_encode", mapOf("content" to content)).expectTextContent("6QA=")
            client.callTool("base64_decode", mapOf("content" to "6QA=")).expectTextContent(content)
            verify(exactly = 1) { base64Utils.encodeToString(content) }
            verify(exactly = 1) { base64Utils.decode("6QA=") }
            verify(exactly = 0) { base64Utils.encodeToString(any<ByteArray>()) }
            verify(exactly = 0) { base64Utils.decode(any<ByteArray>()) }
        }

        @Test
        fun `base64 tools reject unsupported explicit charsets before invoking utilities`() = runBlocking {
            val base64Utils = mockk<Base64Utils>()
            val utilities = mockk<Utilities>()
            every { api.utilities() } returns utilities
            every { utilities.base64Utils() } returns base64Utils
            for (name in listOf("base64_encode", "base64_decode")) {
                for (charset in listOf("", "UTF8", "UTF-16", " UTF-8 ")) {
                    val result = client.callTool(name, mapOf("content" to "dGVzdA==", "charset" to charset))
                    assertTrue(result.expectTextContent().startsWith("Error: charset must be UTF-8 when specified"))
                }
            }
            verify { base64Utils wasNot Called }
        }
        // << mniwa
        
        @Test
        fun `generate random string should work properly`() {
            val randomUtils = mockk<RandomUtils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.randomUtils() } returns randomUtils
            every { randomUtils.randomString(any<Int>(), any<String>()) } returns "1a2b3c1a2b"
            
            runBlocking {
                val result = client.callTool(
                    "generate_random_string", mapOf(
                        "length" to 10,
                        "characterSet" to "abc123"
                    )
                )
                
                delay(100)
                result.expectTextContent("1a2b3c1a2b")
            }
            
            verify(exactly = 1) { randomUtils.randomString(any<Int>(), any<String>()) }
        }
    }
    
    @Nested
    inner class ConfigurationToolsTests {
        @Test
        fun `set task execution engine state should work properly`() {
            val taskExecutionEngine = mockk<TaskExecutionEngine>()
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.taskExecutionEngine() } returns taskExecutionEngine
            every { taskExecutionEngine.state = any() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_task_execution_engine_state", mapOf(
                        "running" to true
                    )
                )
                
                delay(100)
                result.expectTextContent("Task execution engine is now running")
            }
            
            verify(exactly = 1) { taskExecutionEngine.state = TaskExecutionEngine.TaskExecutionEngineState.RUNNING }
            
            clearMocks(taskExecutionEngine, answers = false)
            
            runBlocking {
                val result = client.callTool(
                    "set_task_execution_engine_state", mapOf(
                        "running" to false
                    )
                )
                
                delay(100)
                result.expectTextContent("Task execution engine is now paused")
            }
            
            verify(exactly = 1) { taskExecutionEngine.state = TaskExecutionEngine.TaskExecutionEngineState.PAUSED }
        }
        
        @Test
        fun `set proxy intercept state should work properly`() {
            val proxy = mockk<Proxy>()
            
            every { api.proxy() } returns proxy
            every { proxy.enableIntercept() } just runs
            every { proxy.disableIntercept() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_proxy_intercept_state", mapOf(
                        "intercepting" to true
                    )
                )
                
                delay(100)
                result.expectTextContent("Intercept has been enabled")
            }
            
            verify(exactly = 1) { proxy.enableIntercept() }
            
            clearMocks(proxy, answers = false)
            
            runBlocking {
                val result = client.callTool(
                    "set_proxy_intercept_state", mapOf(
                        "intercepting" to false
                    )
                )
                
                delay(100)
                result.expectTextContent("Intercept has been disabled")
            }
            
            verify(exactly = 1) { proxy.disableIntercept() }
        }
        
        @Test
        fun `config editing tools should respect config settings`() {
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.importProjectOptionsFromJson(any()) } just runs
            every { api.logging().logToOutput(any()) } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_project_options", mapOf(
                        "json" to "{\"test\": true}"
                    )
                )
                
                delay(100)
                result.expectTextContent("Project configuration has been applied")
            }
            
            verify(exactly = 1) { burpSuite.importProjectOptionsFromJson(any()) }
            
            clearMocks(burpSuite, answers = false)
            
            every { config.configEditingTooling } returns false
            
            runBlocking {
                
                val result = client.callTool(
                    "set_project_options", mapOf(
                        "json" to "{\"test\": true}"
                    )
                )
                
                delay(100)
                result.expectTextContent("User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'")
            }
            
            verify(exactly = 0) { burpSuite.importProjectOptionsFromJson(any()) }
        }
    }

    @Nested
    inner class EditorTests {
        @Test
        fun `get active editor contents should handle no editor`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            every { getActiveEditor(api) } returns null
            
            runBlocking {
                val result = client.callTool("get_active_editor_contents", emptyMap())
                
                delay(100)
                result.expectTextContent("<No active editor>")
            }
        }
        
        @Test
        fun `get active editor contents should return text`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            val textArea = mockk<JTextArea>()
            every { getActiveEditor(api) } returns textArea
            every { textArea.text } returns "Editor content"
            
            runBlocking {
                val result = client.callTool("get_active_editor_contents", emptyMap())
                
                delay(100)
                result.expectTextContent("Editor content")
            }
        }
        
        @Test
        fun `set active editor contents should handle no editor`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            every { getActiveEditor(api) } returns null
            
            runBlocking {
                val result = client.callTool(
                    "set_active_editor_contents", mapOf(
                        "text" to "New content"
                    )
                )
                
                delay(100)
                result.expectTextContent("<No active editor>")
            }
        }
        
        @Test
        fun `set active editor contents should handle non-editable editor`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            val textArea = mockk<JTextArea>()
            every { getActiveEditor(api) } returns textArea
            every { textArea.isEditable } returns false
            
            runBlocking {
                val result = client.callTool(
                    "set_active_editor_contents", mapOf(
                        "text" to "New content"
                    )
                )
                
                delay(100)
                result.expectTextContent("<Current editor is not editable>")
            }
        }
        
        @Test
        fun `set active editor contents should update text`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            val textArea = mockk<JTextArea>()
            every { getActiveEditor(api) } returns textArea
            every { textArea.isEditable } returns true
            every { textArea.text = any() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_active_editor_contents", mapOf(
                        "text" to "New content"
                    )
                )
                
                delay(100)
                result.expectTextContent("Editor text has been set")
            }
            
            verify(exactly = 1) { textArea.text = "New content" }
        }
    }
    
    @Nested
    inner class PaginatedToolsTests {
        @Test
        fun `get proxy history should paginate properly`() {
            val proxy = mockk<Proxy>()
            val proxyHistory = listOf(
                mockk<ProxyHttpRequestResponse>(),
                mockk<ProxyHttpRequestResponse>(),
                mockk<ProxyHttpRequestResponse>()
            )
            
            every { api.proxy() } returns proxy
            every { proxy.history() } returns proxyHistory
            
            mockkStatic("net.portswigger.mcp.schema.SerializationKt")
            
            every { proxyHistory[0].toSerializableForm() } returns HttpRequestResponse(
                request = "GET /item1 HTTP/1.1",
                response = "HTTP/1.1 200 OK",
                notes = "Item 1 notes"
            )
            every { proxyHistory[1].toSerializableForm() } returns HttpRequestResponse(
                request = "GET /item2 HTTP/1.1",
                response = "HTTP/1.1 200 OK",
                notes = "Item 2 notes"
            )
            every { proxyHistory[2].toSerializableForm() } returns HttpRequestResponse(
                request = "GET /item3 HTTP/1.1",
                response = "HTTP/1.1 200 OK",
                notes = "Item 3 notes"
            )
            
            runBlocking {
                val result1 = client.callTool(
                    "get_proxy_http_history", mapOf(
                        "count" to 2,
                        "offset" to 0
                    )
                )
                
                delay(100)
                val text1 = result1.expectTextContent()
                assertTrue(text1.contains("GET /item1"))
                assertTrue(text1.contains("GET /item2"))
                assertFalse(text1.contains("GET /item3"))
                
                val result2 = client.callTool(
                    "get_proxy_http_history", mapOf(
                        "count" to 2,
                        "offset" to 2
                    )
                )
                
                delay(100)
                val text2 = result2.expectTextContent()
                assertTrue(text2.contains("GET /item3"))
                
                val result3 = client.callTool(
                    "get_proxy_http_history", mapOf(
                        "count" to 2,
                        "offset" to 3
                    )
                )
                
                delay(100)
                assertEquals("Reached end of items", result3.expectTextContent())
            }
        }

        @Test
        // >> 20261009 mniwa Verify that history JSON preserves complete requests and responses.
        fun `get proxy history should preserve full messages in valid JSON`() {
            val proxy = mockk<Proxy>()
            val historyItem = mockk<ProxyHttpRequestResponse>()
            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(historyItem)

            mockkStatic("net.portswigger.mcp.schema.SerializationKt")
            val original = HttpRequestResponse(
                request = "GET / HTTP/1.1\r\nX-Long: ${"\\\"😀".repeat(2_000)}",
                response = "HTTP/1.1 200 OK\r\n\r\n${"😀".repeat(3_000)}",
                notes = "keep me"
            )
            every { historyItem.toSerializableForm() } returns original

            runBlocking {
                val text = client.callTool(
                    "get_proxy_http_history", mapOf("count" to 1, "offset" to 0)
                ).expectTextContent()
                val item = Json.parseToJsonElement(text).jsonObject

                assertTrue(text.length > 5_000)
                assertEquals(setOf("request", "response", "notes"), item.keys)
                assertEquals(original.request, item.getValue("request").jsonPrimitive.content)
                assertEquals(original.response, item.getValue("response").jsonPrimitive.content)
                assertEquals("keep me", item.getValue("notes").jsonPrimitive.content)
            }
        }
        // << mniwa
    }
    
    @Nested
    inner class CollaboratorToolsTests {
        // >> 20261008 mniwa Verify that the published MCP contract requires full replacement audits after configuration failures.
        @Test
        fun `published scan workflow tools require cancellation and a new full audit after invalid settings`() = runBlocking {
            val tools = client.listTools().associateBy { it.name }
            for (name in listOf("set_project_options", "start_active_scan", "get_active_scan_status")) {
                val description = tools.getValue(name).description!!
                assertTrue(description.contains("Cancel the affected audit through Burp UI"), name)
                assertTrue(description.contains("new full ActiveScan from the beginning"), name)
                assertTrue(description.contains("Pause -> edit -> Resume does not repeat earlier checks"), name)
                assertTrue(description.contains("at least five MCP workflow test sends"), name)
                assertTrue(description.contains("successful Extensions/MCP tests do not prove Scanner"), name)
                assertTrue(description.contains("Ordinary user-requested Pause/Resume with unchanged valid settings"), name)
                assertFalse(description.contains("testing.md"), name)
            }
        }
        // << mniwa

        @Test
        fun `legacy scan tools are absent while Montoya scan tools remain available`() = runBlocking {
            val tools = client.listTools().map { it.name }.toSet()
            for (name in listOf("start_cancelable_active_scan", "get_cancelable_scan_capabilities",
                "get_cancelable_active_scan_status", "cancel_active_scan")) {
                assertFalse(name in tools, name)
            }
            for (name in listOf("start_active_scan", "get_active_scan_status", "get_scanner_issues")) {
                assertTrue(name in tools, name)
            }
        }
        // >> 20261014 mniwa Validate registered status-tool behavior and ETA guidance through MCP without starting a scan.
        @Test
        fun `active scan status workflow preserves empty and lost handle semantics with ETA guidance`() = runBlocking {
            val listed = Json.parseToJsonElement(client.callTool("get_active_scan_status", emptyMap()).expectTextContent()).jsonObject
            assertEquals("true", listed["success"]!!.jsonPrimitive.content)
            assertEquals("[]", listed["audits"].toString())
            val missing = Json.parseToJsonElement(client.callTool("get_active_scan_status", mapOf("auditId" to "unknown")).expectTextContent()).jsonObject
            assertEquals("AUDIT_NOT_TRACKED", missing["errorCode"]!!.jsonPrimitive.content)
            val description = client.listTools().single { it.name == "get_active_scan_status" }.description!!
            assertTrue(description.contains("timeEstimate"))
            assertTrue(description.contains("no additional calibration scans"))
            assertTrue(description.contains("not statistical confidence intervals"))
            val supplied = mapOf("requestsPerInsertionPoint" to 40.0, "basis" to "Observed check evidence", "workflowSeconds" to 15.0, "effectiveConcurrency" to 1.0)
            val withModel = Json.parseToJsonElement(client.callTool("get_active_scan_status", mapOf("auditId" to "unknown", "workload" to supplied)).expectTextContent()).jsonObject
            assertEquals("AUDIT_NOT_TRACKED", withModel["errorCode"]!!.jsonPrimitive.content)
            // >> 20261014 mniwa Verify default workload decoding through MCP and reject invalid timing before starting an audit.
            assertTrue(description.contains("defaults to 34"))
            val defaults = Json.parseToJsonElement(client.callTool("get_active_scan_status", mapOf("auditId" to "unknown", "workload" to mapOf("workflowSeconds" to 2.0))).expectTextContent()).jsonObject
            assertEquals("AUDIT_NOT_TRACKED", defaults["errorCode"]!!.jsonPrimitive.content)
            val invalidStart = client.callTool("start_active_scan", mapOf("host" to "localhost", "port" to 80, "protocol" to "http", "request" to "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", "workload" to mapOf("workflowSeconds" to -1.0))).expectTextContent()
            assertTrue(invalidStart.startsWith("Error: workflowSeconds must be finite and positive"))
            // << mniwa
            assertTrue(client.callTool("get_active_scan_status", mapOf("workload" to supplied)).expectTextContent().startsWith("Error: auditId is required"))
        }
        // << mniwa
        private val collaborator = mockk<Collaborator>()
        private val collaboratorClient = mockk<CollaboratorClient>()
        private val collaboratorServer = mockk<CollaboratorServer>()

        @BeforeEach
        fun setupCollaborator() {
            mockkStatic(InteractionFilter::class)

            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            val version = mockk<burp.api.montoya.core.Version>()
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.version() } returns version
            every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL
            every { burpSuite.taskExecutionEngine() } returns mockk(relaxed = true)
            every { burpSuite.exportProjectOptionsAsJson() } returns "{}"
            every { burpSuite.exportUserOptionsAsJson() } returns "{}"
            every { burpSuite.importProjectOptionsFromJson(any()) } just runs
            every { burpSuite.importUserOptionsFromJson(any()) } just runs

            every { api.collaborator() } returns collaborator
            every { collaborator.createClient() } returns collaboratorClient
            every { collaboratorClient.server() } returns collaboratorServer
            every { collaboratorServer.address() } returns "burpcollaborator.net"

            serverManager.stop {}
            serverStarted = false
            serverManager.start(config) { state ->
                if (state is ServerState.Running) serverStarted = true
            }

            runBlocking {
                var attempts = 0
                while (!serverStarted && attempts < 30) {
                    delay(100)
                    attempts++
                }
                if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")
                client.connectToServer("http://127.0.0.1:${testPort}")
            }
        }

        @AfterEach
        fun cleanupCollaborator() {
            unmockkStatic(InteractionFilter::class)
        }

        private fun mockInteraction(
            id: String,
            type: InteractionType,
            clientIp: String = "10.0.0.1",
            clientPort: Int = 54321,
            customData: String? = null,
            dnsDetails: DnsDetails? = null,
            httpDetails: HttpDetails? = null,
            smtpDetails: SmtpDetails? = null
        ): Interaction {
            val interactionId = mockk<InteractionId>()
            every { interactionId.toString() } returns id

            return mockk<Interaction>().also {
                every { it.id() } returns interactionId
                every { it.type() } returns type
                every { it.timeStamp() } returns ZonedDateTime.parse("2025-01-01T12:00:00Z")
                every { it.clientIp() } returns InetAddress.getByName(clientIp)
                every { it.clientPort() } returns clientPort
                every { it.customData() } returns Optional.ofNullable(customData)
                every { it.dnsDetails() } returns Optional.ofNullable(dnsDetails)
                every { it.httpDetails() } returns Optional.ofNullable(httpDetails)
                every { it.smtpDetails() } returns Optional.ofNullable(smtpDetails)
            }
        }

        @Test
        fun `generate payload should return payload and server info`() {
            val payload = mockk<CollaboratorPayload>()
            val payloadId = mockk<InteractionId>()
            every { payload.toString() } returns "abc123.burpcollaborator.net"
            every { payload.id() } returns payloadId
            every { payloadId.toString() } returns "abc123"
            every { collaboratorClient.generatePayload() } returns payload

            runBlocking {
                val result = client.callTool("generate_collaborator_payload", emptyMap())
                delay(100)
                result.expectTextContent(
                    "Payload: abc123.burpcollaborator.net\n" +
                    "Payload ID: abc123\n" +
                    "Collaborator server: burpcollaborator.net"
                )
            }

            verify(exactly = 1) { collaboratorClient.generatePayload() }
        }

        @Test
        fun `generate payload with custom data should pass custom data`() {
            val payload = mockk<CollaboratorPayload>()
            val payloadId = mockk<InteractionId>()
            every { payload.toString() } returns "custom123.burpcollaborator.net"
            every { payload.id() } returns payloadId
            every { payloadId.toString() } returns "custom123"
            every { collaboratorClient.generatePayload(any<String>()) } returns payload

            runBlocking {
                val result = client.callTool(
                    "generate_collaborator_payload", mapOf(
                        "customData" to "mydata"
                    )
                )
                delay(100)
                result.expectTextContent(
                    "Payload: custom123.burpcollaborator.net\n" +
                    "Payload ID: custom123\n" +
                    "Collaborator server: burpcollaborator.net"
                )
            }

            verify(exactly = 1) { collaboratorClient.generatePayload("mydata") }
        }

        @Test
        fun `get interactions should return dns interaction details`() {
            val dnsDetails = mockk<DnsDetails>().also {
                every { it.queryType() } returns DnsQueryType.A
            }
            val interaction = mockInteraction("int-001", InteractionType.DNS, dnsDetails = dnsDetails)
            every { collaboratorClient.getAllInteractions() } returns listOf(interaction)

            runBlocking {
                val result = client.callTool("get_collaborator_interactions", emptyMap())
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"id\":\"int-001\""))
                assertTrue(text.contains("\"type\":\"DNS\""))
                assertTrue(text.contains("\"queryType\":\"A\""))
                assertTrue(text.contains("\"clientIp\":\"10.0.0.1\""))
            }

            verify(exactly = 1) { collaboratorClient.getAllInteractions() }
        }

        @Test
        fun `get interactions should return http interaction details`() {
            val mockRequest = mockk<burp.api.montoya.http.message.requests.HttpRequest>()
            every { mockRequest.toString() } returns "GET / HTTP/1.1"
            val mockResponse = mockk<burp.api.montoya.http.message.responses.HttpResponse>()
            every { mockResponse.toString() } returns "HTTP/1.1 200 OK"
            val mockRequestResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            every { mockRequestResponse.request() } returns mockRequest
            every { mockRequestResponse.response() } returns mockResponse

            val httpDetails = mockk<HttpDetails>().also {
                every { it.protocol() } returns HttpProtocol.HTTP
                every { it.requestResponse() } returns mockRequestResponse
            }
            val interaction = mockInteraction("int-002", InteractionType.HTTP, httpDetails = httpDetails)
            every { collaboratorClient.getAllInteractions() } returns listOf(interaction)

            runBlocking {
                val result = client.callTool("get_collaborator_interactions", emptyMap())
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"type\":\"HTTP\""))
                assertTrue(text.contains("\"protocol\":\"HTTP\""))
                assertTrue(text.contains("GET / HTTP/1.1"))
                assertTrue(text.contains("HTTP/1.1 200 OK"))
            }

            verify(exactly = 1) { collaboratorClient.getAllInteractions() }
        }

        @Test
        fun `get interactions should return smtp interaction details`() {
            val smtpDetails = mockk<SmtpDetails>().also {
                every { it.protocol() } returns SmtpProtocol.SMTP
                every { it.conversation() } returns "EHLO test\r\n250 OK"
            }
            val interaction = mockInteraction("int-003", InteractionType.SMTP, smtpDetails = smtpDetails)
            every { collaboratorClient.getAllInteractions() } returns listOf(interaction)

            runBlocking {
                val result = client.callTool("get_collaborator_interactions", emptyMap())
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"type\":\"SMTP\""))
                assertTrue(text.contains("\"protocol\":\"SMTP\""))
                assertTrue(text.contains("EHLO test"))
            }

            verify(exactly = 1) { collaboratorClient.getAllInteractions() }
        }

        @Test
        fun `get interactions with payloadId should use filter`() {
            val mockFilter = mockk<InteractionFilter>()
            every { InteractionFilter.interactionIdFilter("abc123") } returns mockFilter
            every { collaboratorClient.getInteractions(mockFilter) } returns emptyList()

            runBlocking {
                val result = client.callTool(
                    "get_collaborator_interactions", mapOf(
                        "payloadId" to "abc123"
                    )
                )
                delay(100)
                result.expectTextContent("No interactions detected")
            }

            verify(exactly = 1) { collaboratorClient.getInteractions(mockFilter) }
        }

        @Test
        fun `get interactions should return no interactions message when empty`() {
            every { collaboratorClient.getAllInteractions() } returns emptyList()

            runBlocking {
                val result = client.callTool("get_collaborator_interactions", emptyMap())
                delay(100)
                result.expectTextContent("No interactions detected")
            }
        }
    }

    @Test
    fun `tool name conversion should work properly`() {
        assertEquals("send_http1_request", "SendHttp1Request".toLowerSnakeCase())
        assertEquals("test_case_conversion", "TestCaseConversion".toLowerSnakeCase())
        assertEquals("multiple_upper_case_letters", "MultipleUpperCaseLetters".toLowerSnakeCase())
    }
    
    @Test
    fun `edition specific tools should only register in professional edition`() {
        val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
        val version = mockk<burp.api.montoya.core.Version>()
        
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.version() } returns version
        
        every { version.edition() } returns BurpSuiteEdition.COMMUNITY_EDITION
        runBlocking {
            val tools = client.listTools()
            assertFalse(tools.any { it.name == "get_scanner_issues" })
            assertFalse(tools.any { it.name == "generate_collaborator_payload" })
            assertFalse(tools.any { it.name == "get_collaborator_interactions" })
        }

        every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL

        serverManager.stop {}
        serverStarted = false
        serverManager.start(config) { state ->
            if (state is ServerState.Running) serverStarted = true
        }

        runBlocking {
            var attempts = 0
            while (!serverStarted && attempts < 30) {
                delay(100)
                attempts++
            }
            if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")

            client.connectToServer("http://127.0.0.1:${testPort}")

            val tools = client.listTools()
            assertTrue(tools.any { it.name == "get_scanner_issues" })
            assertTrue(tools.any { it.name == "generate_collaborator_payload" })
            assertTrue(tools.any { it.name == "get_collaborator_interactions" })
        }
    }
}
