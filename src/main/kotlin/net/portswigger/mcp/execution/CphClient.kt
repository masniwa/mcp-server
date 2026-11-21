package net.portswigger.mcp.execution

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import java.net.HttpURLConnection
import java.net.URI

class CphClient private constructor(
    private val token:String?,
    private val startupConnection:JsonObject?,
    private val readTimeoutFor:(String)->Int
) {
    constructor(token:String?=null,startupConnection:JsonObject?=null):this(
        token,startupConnection,{ path -> if(path=="/cph/import" || path=="/cph/import-atomic" || path=="/cph/prune") 120000 else 30000 }
    )
    internal constructor(token:String?,startupConnection:JsonObject?,defaultReadTimeout:Int,importReadTimeout:Int):this(
        token,startupConnection,{ path -> if(path=="/cph/import" || path=="/cph/import-atomic" || path=="/cph/prune") importReadTimeout else defaultReadTimeout }
    )
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
            conn.connectTimeout=5000;conn.readTimeout=readTimeoutFor(path)
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
    fun activity():JsonObject {
        val (status, body) = exchange("/cph/health")
        val response = jobJson.parseToJsonElement(body).jsonObject
        requireJob(status in 200..299 && response["success"] == JsonPrimitive(true), "CPH_ACTIVITY_UNAVAILABLE")
        if (token != null) requireJob(response["managed"] == JsonPrimitive(true), "CPH_MANAGEMENT_NOT_ACTIVE")
        requireJob(runtimeMatches(response) != false, "CPH_RUNTIME_MISMATCH")
        return response["activity"] as? JsonObject ?: throw JobRejected("CPH_ACTIVITY_UNSUPPORTED")
    }
    fun export():JsonObject {
        val (status,body)=exchange("/cph/export")
        val value=jobJson.parseToJsonElement(body).jsonObject
        requireJob(status in 200..299 && value["success"]?.jsonPrimitive?.booleanOrNull==true,"CPH_EXPORT_FAILED")
        if(token!=null) requireJob(value["managed"]?.jsonPrimitive?.booleanOrNull==true,"CPH_MANAGEMENT_NOT_ACTIVE")
        requireJob(runtimeMatches(value)!=false,"CPH_RUNTIME_MISMATCH")
        return value["config"]?.jsonObject ?: throw JobRejected("CPH_CONFIG_MISSING")
    }
    fun apply(config:JsonObject,order:List<String>,expected:JsonObject,operationId:String) {
        requireJob(config.keys==order.toSet() && order.size==config.size,"CPH_ORDER_INCONSISTENT")
        val ordered=JsonObject(order.associateWith { config.getValue(it) })
        val payload=buildJsonObject { put("operationId",operationId);put("expected",expected);put("config",ordered) }
        val (status,body)=exchange("/cph/import-atomic",payload.toString())
        val result=runCatching { jobJson.parseToJsonElement(body).jsonObject }.getOrNull()
        if(status==404) throw JobRejected("CPH_ATOMIC_IMPORT_UNAVAILABLE")
        if(status !in 200..299 || result?.get("success")?.jsonPrimitive?.booleanOrNull!=true ||
            result["operationId"]?.jsonPrimitive?.contentOrNull!=operationId) {
            val allowed=setOf("CPH_FIELD_SHAPE_INVALID","CPH_SINGLE_LINE_CONTROL_CHARACTER","UNSUPPORTED_CPH_FIELD",
                "CPH_TAB_NAME_INVALID","CPH_IMPORT_BASELINE_CHANGED","CPH_IMPORT_READBACK_MISMATCH",
                "CPH_CACHE_REFERENCE_REQUIRED","CPH_CACHE_REFERENCE_ORDER","CPH_CACHE_REFERENCE_CYCLE",
                "CPH_CACHE_REFERENCE_CONFLICT","CPH_CACHE_REFERENCE_NOT_RESTORED",
                "CPH_ROLLBACK_OUTCOME_UNKNOWN","CPH_IMPORT_FAILED","CPH_SETTER_FAILED","CPH_DUPLICATE_JSON_KEY")
            val code=result?.get("code")?.jsonPrimitive?.contentOrNull?.takeIf { it in allowed } ?: "CPH_IMPORT_FAILED_OR_UNKNOWN"
            val details=listOf("tabName","fieldName","stage","exceptionClass").mapNotNull { key ->
                result?.get(key)?.jsonPrimitive?.contentOrNull?.takeIf { it.length<=160 && it.none(Char::isISOControl) }?.let { key to it }
            }.toMap()
            throw JobRejected(code,details)
        }
    }
    fun prune(names:List<String>,expected:JsonObject) {
        val payload=buildJsonObject {
            put("names",JsonArray(names.map(::JsonPrimitive)))
            put("expected",expected)
        }
        val (status,body)=exchange("/cph/prune",payload.toString())
        val result=jobJson.parseToJsonElement(body).jsonObject
        requireJob(status in 200..299 && result["success"]?.jsonPrimitive?.booleanOrNull==true &&
            result["removedCount"]?.jsonPrimitive?.intOrNull==names.size,"CPH_PRUNE_FAILED_OR_UNKNOWN")
    }
}
