package net.portswigger.mcp.execution

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import java.net.HttpURLConnection
import java.net.URI

class CphClient(private val token:String?=null) {
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
        return value["config"]?.jsonObject ?: throw JobRejected("CPH_CONFIG_MISSING")
    }
    fun apply(config:JsonObject,order:List<String>) {
        val ordered=JsonObject(order.associateWith { config.getValue(it) })
        val (status,body)=exchange("/cph/import",ordered.toString())
        val result=jobJson.parseToJsonElement(body).jsonObject
        requireJob(status in 200..299 && result["success"]?.jsonPrimitive?.booleanOrNull==true,"CPH_IMPORT_FAILED_OR_UNKNOWN")
    }
}
