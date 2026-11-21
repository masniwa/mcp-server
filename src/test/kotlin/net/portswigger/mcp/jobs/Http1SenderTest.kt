package net.portswigger.mcp.jobs

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import io.mockk.*
import net.portswigger.diagnosis.contract.JobRejected
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.execution.*
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.UserApprovalHandler
import net.portswigger.mcp.tools.SendHttp1Request
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class Http1SenderTest {
    @Test fun `native return with no HTTP response ends the correlated send but remains a failed probe`() {
        mockkStatic(HttpService::class);mockkStatic(HttpRequest::class)
        try {
            val api=mockk<MontoyaApi>(relaxed=true);val config=mockk<McpConfig>(relaxed=true)
            every { config.requireHttpRequestApproval } returns false
            val service=mockk<HttpService>();val request=mockk<HttpRequest>();val exchange=mockk<HttpRequestResponse>()
            val raw="GET /read HTTP/1.1\r\nHost: fixture.invalid:8080\r\n\r\n"
            val capturedService=net.portswigger.mcp.schema.HttpService("fixture.invalid",8080,false)
            val history=net.portswigger.mcp.tools.LoggerHttpHistory()
            every { HttpService.httpService("fixture.invalid",8080,false) } returns service
            every { HttpRequest.httpRequest(service,any<String>()) } returns request
            every { request.toString() } returns raw;every { request.httpService() } returns service
            every { service.host() } returns capturedService.host;every { service.port() } returns 8080;every { service.secure() } returns false
            every { exchange.request() } returns request;every { exchange.response() } returns null
            every { api.http().sendRequest(request) } answers {
                assertFalse(history.quiescent(setOf(capturedService)))
                history.recordRequest(1,"EXTENSIONS",capturedService,"http://fixture.invalid:8080/read",raw,null)
                assertFalse(history.quiescent(setOf(capturedService)))
                exchange
            }
            val result=Http1Sender(api).send(SendHttp1Request(raw,"fixture.invalid",8080,false),config,history)
            assertEquals("HTTP_PROBE_DENIED_OR_NO_RESPONSE",assertThrows(JobRejected::class.java) { result.responseText() }.code)
            assertTrue(history.quiescent(setOf(capturedService)))
            val item=history.snapshot().single()
            assertEquals("NO_RESPONSE_OBSERVED",item.responseState);assertNull(item.response)
            assertEquals("SEND_RETURNED",item.sendCompletionState)
            verify(exactly=1) { api.http().sendRequest(request) }
        } finally { unmockkStatic(HttpRequest::class);unmockkStatic(HttpService::class) }
    }

    @Test fun `native exchange display and selected HTTP response have independent projections`() {
        mockkStatic(HttpService::class);mockkStatic(HttpRequest::class)
        try {
            val api=mockk<MontoyaApi>(relaxed=true)
            val config=mockk<McpConfig>(relaxed=true)
            every { config.requireHttpRequestApproval } returns false
            val service=mockk<HttpService>();val request=mockk<HttpRequest>()
            val exchange=mockk<HttpRequestResponse>();val selected=mockk<HttpResponse>()
            val raw="POST /target HTTP/1.1\nHost: test.invalid:8080\n\nhttpResponse=body, messageAnnotations=must remain"
            val response="HTTP/1.1 200 OK\r\n\r\nselected macro response, messageAnnotations=body value}"
            val display="HttpRequestResponse{httpRequest=request, httpResponse=$response, messageAnnotations=Annotations{comment=''}}"
            val normalized=slot<String>()
            every { HttpService.httpService("test.invalid",8080,false) } returns service
            every { HttpRequest.httpRequest(service,capture(normalized)) } returns request
            every { api.http().sendRequest(request) } returns exchange
            every { exchange.toString() } returns display
            every { exchange.response() } returns selected
            every { selected.toString() } returns response
            val result=Http1Sender(api).send(SendHttp1Request(raw,"test.invalid",8080,false),config)
            assertEquals(display,result.legacyText())
            assertEquals(response,result.responseText())
            assertEquals(raw.replace("\n","\r\n"),normalized.captured)
            verify(exactly=1) { api.http().sendRequest(request) }
        } finally { unmockkStatic(HttpRequest::class);unmockkStatic(HttpService::class) }
    }

    @Test fun `both projections respect an existing human HTTP denial before transport`() {
        val api=mockk<MontoyaApi>(relaxed=true);val config=mockk<McpConfig>(relaxed=true)
        every { config.requireHttpRequestApproval } returns true
        every { config.getAutoApproveTargetsList() } returns emptyList()
        val previous=HttpRequestSecurity.approvalHandler
        HttpRequestSecurity.approvalHandler=object:UserApprovalHandler {
            override suspend fun requestApproval(hostname:String,port:Int,config:McpConfig,requestContent:String?,api:MontoyaApi?)=false
        }
        try {
            val result=Http1Sender(api).send(SendHttp1Request("GET / HTTP/1.1\r\nHost: test.invalid\r\n\r\n","test.invalid",80,false),config)
            assertEquals("Send HTTP request denied by Burp Suite",result.legacyText())
            assertEquals("HTTP_PROBE_DENIED_OR_NO_RESPONSE",assertThrows(JobRejected::class.java) { result.responseText() }.code)
            verify(exactly=0) { api.http().sendRequest(any()) }
        } finally { HttpRequestSecurity.approvalHandler=previous }
    }

    @Test fun `absent selected response is refused without decoding a native display string`() {
        assertEquals("<no response>",Http1SendResult(false,null).legacyText())
        assertThrows(JobRejected::class.java) { Http1SendResult(false,null).responseText() }
        val exchange=mockk<HttpRequestResponse>()
        every { exchange.response() } returns null
        every { exchange.toString() } returns "HttpRequestResponse{httpRequest=request, httpResponse=null}"
        assertThrows(JobRejected::class.java) { Http1SendResult(false,exchange).responseText() }
    }
}
