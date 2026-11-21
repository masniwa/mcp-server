package net.portswigger.mcp.schema

import kotlinx.serialization.Required
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.*
import net.portswigger.mcp.jobs.DiagnosticJob
import net.portswigger.mcp.jobs.ReviewWorkflowEvidence
import net.portswigger.mcp.tools.GetProxyHttpHistory
import net.portswigger.mcp.tools.GetProxyHttpHistoryRegex
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class JsonSchemaOptionalTest {
    @Serializable data class Input(val name:String,val enabled:Boolean=false,val count:Int=5,
        val names:List<String> = emptyList(),val nullable:String?=null,@Required val explicit:Boolean=false)

    @Test fun `decoder defaults are optional while genuine and annotated requirements stay required`() {
        val schema=Input::class.asInputSchema()
        assertEquals(setOf("name","explicit"),schema.required!!.toSet())
        assertEquals(JsonPrimitive("boolean"),schema.properties!!["enabled"]!!.jsonObject["type"])
        assertEquals(JsonPrimitive("integer"),schema.properties!!["count"]!!.jsonObject["type"])
        assertEquals(JsonPrimitive("array"),schema.properties!!["names"]!!.jsonObject["type"])
        assertFalse("nullable" in schema.required!!)
        assertThrows(SerializationException::class.java) { Json.decodeFromString<Input>("""{"name":"fixture"}""") }
        assertEquals(Input("fixture",explicit=true),Json.decodeFromString<Input>("""{"name":"fixture","explicit":true}"""))
    }
    @Test fun `both history schemas retain real requirements and make includeRequestIds optional`() {
        assertEquals(setOf("count","offset"),GetProxyHttpHistory::class.asInputSchema().required!!.toSet())
        assertEquals(setOf("count","offset","regex"),GetProxyHttpHistoryRegex::class.asInputSchema().required!!.toSet())
        for(schema in listOf(GetProxyHttpHistory::class.asInputSchema(),GetProxyHttpHistoryRegex::class.asInputSchema())) {
            assertEquals(JsonPrimitive("boolean"),schema.properties!!["includeRequestIds"]!!.jsonObject["type"])
        }
        assertFalse(Json.decodeFromString<GetProxyHttpHistory>("""{"count":1,"offset":0}""").includeRequestIds)
        assertFalse(Json.decodeFromString<GetProxyHttpHistoryRegex>("""{"count":1,"offset":0,"regex":"x"}""").includeRequestIds)
        for(flag in listOf(true,false)) assertEquals(flag,Json.decodeFromString<GetProxyHttpHistory>("""{"count":1,"offset":0,"includeRequestIds":$flag}""").includeRequestIds)
        assertThrows(SerializationException::class.java) { Json.decodeFromString<GetProxyHttpHistory>("""{"offset":0}""") }
    }
    @Test fun `managed job and evidence review retain required identities with unchanged runtime defaults`() {
        assertEquals(setOf("action","executionId"),DiagnosticJob::class.asInputSchema().required!!.toSet())
        assertEquals(setOf("planJson"),ReviewWorkflowEvidence::class.asInputSchema().required!!.toSet())
        val job=Json.decodeFromString<DiagnosticJob>("""{"action":"status","executionId":"fixture"}""")
        assertEquals(0,job.index);assertEquals(0,job.offset);assertEquals(20,job.count)
        assertThrows(SerializationException::class.java) { Json.decodeFromString<DiagnosticJob>("""{"action":"status"}""") }
    }
}
