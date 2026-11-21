package net.portswigger.mcp.execution

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import kotlinx.coroutines.runBlocking
import net.portswigger.diagnosis.contract.requireJob
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.tools.SendHttp1Request
import net.portswigger.mcp.tools.LoggerHttpHistory
import net.portswigger.mcp.tools.normalizeHttpContent

/** One permission and transport implementation; native exchange display is not a wire format. */
class Http1Sender(private val api:MontoyaApi) {
    fun send(input:SendHttp1Request,config:McpConfig,history:LoggerHttpHistory?=null):Http1SendResult {
        val allowed=runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(input.targetHostname,input.targetPort,config,input.content,api)
        }
        if(!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: ${input.targetHostname}:${input.targetPort}")
            return Http1SendResult(true,null)
        }
        api.logging().logToOutput("MCP HTTP/1.1 request: ${input.targetHostname}:${input.targetPort}")
        val request=HttpRequest.httpRequest(input.toMontoyaService(),normalizeHttpContent(input.content))
        val service=net.portswigger.mcp.schema.HttpService(input.targetHostname,input.targetPort,input.usesHttps)
        val observation=history?.beginSend(service,request.toString())
        var exchange:HttpRequestResponse?=null
        try {
            exchange=api.http().sendRequest(request)
            return Http1SendResult(false,exchange)
        } finally {
            if(observation!=null) {
                val returned=runCatching { exchange?.request() }.getOrNull()
                val returnedService=runCatching { returned?.httpService()?.let {
                    net.portswigger.mcp.schema.HttpService(it.host(),it.port(),it.secure())
                } }.getOrNull()
                history.endSend(observation,returnedService,runCatching { returned?.toString() }.getOrNull())
            }
        }
    }
}

data class Http1SendResult(val denied:Boolean,val exchange:HttpRequestResponse?) {
    fun legacyText():String = if(denied) "Send HTTP request denied by Burp Suite" else exchange?.toString() ?: "<no response>"
    fun responseText():String {
        requireJob(!denied,"HTTP_PROBE_DENIED_OR_NO_RESPONSE")
        val response=exchange?.response()
        requireJob(response!=null,"HTTP_PROBE_DENIED_OR_NO_RESPONSE")
        return response!!.toString()
    }
}
