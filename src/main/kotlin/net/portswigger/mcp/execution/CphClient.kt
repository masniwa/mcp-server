package net.portswigger.mcp.execution

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import java.net.HttpURLConnection
import java.net.URI

class CphClient(private val token:String?=null,private val startupConnection:JsonObject?=null) {
    private fun runtimeMatches(response:JsonObject):Boolean? {
        val actual=response["connection"] as? JsonObject ?: return null
        if(startupConnection?.get("source")?.jsonPrimitive?.contentOrNull!="file" ||
            actual["source"]?.jsonPrimitive?.contentOrNull!="file") return null
        val expected=startupConnection["runtimeDirectory"]?.jsonPrimitive?.contentOrNull ?: return null
        val reported=actual["runtimeDirectory"]?.jsonPrimitive?.contentOrNull ?: return null
        return runCatching { java.nio.file.Path.of(expected).toAbsolutePath().normalize()==java.nio.file.Path.of(reported).toAbsolutePath().normalize() }.getOrNull()
    }
    fun readConfiguration(host:String="127.0.0.1",port:Int=17866):String {
        val (status,body)=exchange("/cph/export",host=host,port=port)
        val response=runCatching { jobJson.parseToJsonElement(body).jsonObject }.getOrNull()
        return buildJsonObject {
            if(status in 200..299 && response!=null) response.forEach { (key,value) -> put(key,value) }
            else { put("success",false);put("status",status);put("body",body) }
            put("connectionDiagnostics",buildJsonObject {
                startupConnection?.let { put("mcp",it) }
                put("host",host);put("port",port)
                val same=response?.let(::runtimeMatches)
                put("runtimeMatches",same?.let { JsonPrimitive(it) } ?: JsonNull)
                if(status==403 && response?.get("message")?.jsonPrimitive?.contentOrNull=="CPH_AUTH_REQUIRED") {
                    put("code","CPH_AUTH_REQUIRED")
                    put("guidance","Check the selected MCP JAR and CPH paths with configure-runtime.ps1 (read-only default). Runtime selection and credentials are retained at extension startup. Do not reload during diagnosis; configure only in stopped maintenance. Never copy or print secrets, edit job ledgers, or disable authentication.")
                }
            })
        }.toString()
    }
    fun exchange(path:String,body:String?=null,host:String="127.0.0.1",port:Int=17866):Pair<Int,String> {
        requireJob(token==null || host=="127.0.0.1" && port==17866,"CPH_TOKEN_DESTINATION_FORBIDDEN")
        val authorization=token?.let { "Bearer $it" } ?: net.portswigger.mcp.security.LocalCphCredentials.authorization(host,port)
        val conn=URI("http",null,host,port,path,null,null).toURL().openConnection() as HttpURLConnection
        return try {
            conn.instanceFollowRedirects=false
            conn.connectTimeout=5000;conn.readTimeout=30000
            authorization?.let { conn.setRequestProperty("Authorization",it) }
            conn.setRequestProperty("Accept","application/json")
            if(body!=null) {
                conn.requestMethod="POST";conn.doOutput=true;conn.setRequestProperty("Content-Type","application/json; charset=utf-8")
                conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            }
            val status=conn.responseCode
            val text=(if(status in 200..299) conn.inputStream else conn.errorStream)?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
            status to text
        } finally { conn.disconnect() }
    }
    fun export():JsonObject {
        val (status,body)=exchange("/cph/export")
        val value=jobJson.parseToJsonElement(body).jsonObject
        requireJob(status in 200..299 && value["success"]?.jsonPrimitive?.booleanOrNull==true,"CPH_EXPORT_FAILED")
        if(token!=null) requireJob(value["managed"]?.jsonPrimitive?.booleanOrNull==true,"CPH_MANAGEMENT_NOT_ACTIVE")
        requireJob(runtimeMatches(value)!=false,"CPH_RUNTIME_MISMATCH")
        return value["config"]?.jsonObject ?: throw JobRejected("CPH_CONFIG_MISSING")
    }
    fun apply(config:JsonObject,order:List<String>) {
        val ordered=JsonObject(order.associateWith { config.getValue(it) })
        val (status,body)=exchange("/cph/import",ordered.toString())
        val result=jobJson.parseToJsonElement(body).jsonObject
        requireJob(status in 200..299 && result["success"]?.jsonPrimitive?.booleanOrNull==true,"CPH_IMPORT_FAILED_OR_UNKNOWN")
    }
}
