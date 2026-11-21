package net.portswigger.mcp.jobs

import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import net.portswigger.mcp.tools.mcpTool
import net.portswigger.mcp.tools.RATE_LIMIT_OBSERVATION_GUIDANCE
import net.portswigger.mcp.tools.resolvePayloadJsonContainers
import net.portswigger.diagnosis.contract.fingerprint

@Serializable data class ReviewWorkflowEvidence(val planJson:String, val executionId:String?=null, val evidenceJson:String?=null)

/** Pure, read-only comparisons. No sender, configuration writer, scanner or approval dependency. */
internal object WorkflowEvidenceReview {
    val categories=listOf("AUTHENTICATION","CSRF","SESSION_LOGOUT","INPUT_PRESERVATION","ATTRIBUTE_RESTORATION")
    private class Uncertain(val reason:String):RuntimeException()
    private fun need(ok:Boolean, reason:String) { if(!ok) throw Uncertain(reason) }
    private fun JsonObject.s(key:String)=this[key]?.jsonPrimitive?.contentOrNull
    private fun obj(value:JsonElement?)=value as? JsonObject ?: throw Uncertain("OBJECT_REQUIRED")
    private fun array(value:JsonElement?)=value as? JsonArray ?: throw Uncertain("ARRAY_REQUIRED")
    private fun strict(text:String, maxBytes:Int=1024*1024):JsonElement {
        // Reuse the existing byte-aware parser to reject duplicate keys, controls and excessive nesting.
        resolvePayloadJsonContainers(("HTTP/1.1 200 OK\r\n\r\n"+text).toByteArray(Charsets.UTF_8),listOf(""),maxBytes)
        return Json.parseToJsonElement(text)
    }
    fun parse(text:String):JsonObject { require(text.length<=16*1024*1024) { "REVIEW_INPUT_TOO_LARGE" };return obj(strict(text,16*1024*1024)) }
    fun probeFlows(probes:List<JsonObject>):JsonArray = JsonArray(probes.mapIndexed { i,p ->
        val logger=obj(p["logger"]);val before=obj(logger["before"])["latestId"]!!.jsonPrimitive.long
        val after=obj(logger["after"])["latestId"]!!.jsonPrimitive.long
        @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
        val entries=array(logger["pages"]).flatMap { page ->
            Json.decodeToSequence<JsonObject>(page.jsonPrimitive.content.byteInputStream(),DecodeSequenceMode.WHITESPACE_SEPARATED).toList()
        }.filter { it["id"]!!.jsonPrimitive.long in (before+1)..after }
        buildJsonObject { put("id","probe-$i");put("variantId",p["variantId"]!!);put("branch",p["branch"]!!);put("entries",JsonArray(entries)) }
    })
    private fun headers(raw:String):List<Pair<String,String>> {
        val end=raw.indexOf("\r\n\r\n");need(end>=0,"HTTP_HEADERS_MISSING")
        return raw.substring(0,end).split("\r\n").drop(1).map {
            need(it.contains(':') && !it.startsWith(' ') && !it.startsWith('\t'),"AMBIGUOUS_HEADERS")
            it.substringBefore(':').lowercase() to it.substringAfter(':').trim()
        }
    }
    private fun one(values:List<String>):String { need(values.size==1,"MISSING_OR_AMBIGUOUS_VALUE");return values.single() }
    private fun formPart(text:String):String {
        val bytes=java.io.ByteArrayOutputStream();var i=0
        while(i<text.length) {
            val c=text[i++]
            when(c) {
                '%' -> { need(i+1<text.length,"INVALID_FORM_ENCODING");val hex=text.substring(i,i+2);need(hex.all { it.digitToIntOrNull(16)!=null },"INVALID_FORM_ENCODING");bytes.write(hex.toInt(16));i+=2 }
                '+' -> bytes.write(32)
                else -> { need(c.code<128,"FORM_REQUIRES_PERCENT_ENCODED_UTF8");bytes.write(c.code) }
            }
        }
        return Charsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(bytes.toByteArray())).toString()
    }
    private fun value(ref:JsonObject, stages:Map<String,JsonObject?>):Pair<JsonElement,JsonObject> {
        val row=stages[ref.s("stage")] ?: throw Uncertain("MISSING_OR_AMBIGUOUS_STAGE")
        val side=ref.s("side");need(side in listOf("request","response"),"INVALID_SIDE")
        val raw=row[side]?.jsonPrimitive?.contentOrNull ?: throw Uncertain("RESPONSE_NOT_OBSERVED")
        if(side=="response") need(row.s("responseState")=="RESPONSE_RECEIVED","RESPONSE_NOT_OBSERVED")
        val field=ref.s("field")
        val result:JsonElement=when(field) {
            "status" -> { need(side=="response","STATUS_REQUIRES_RESPONSE");JsonPrimitive(raw.substringBefore("\r\n").split(' ').getOrNull(1)?.toIntOrNull() ?: throw Uncertain("INVALID_HTTP_STATUS")) }
            "header" -> JsonPrimitive(one(headers(raw).filter { it.first.equals(ref.s("name"),true) }.map { it.second }))
            "form" -> {
                val type=one(headers(raw).filter { it.first=="content-type" }.map { it.second })
                need(type.substringBefore(';').equals("application/x-www-form-urlencoded",true),"FORM_CONTENT_TYPE_REQUIRED")
                need(type.split(';').drop(1).none { it.trim().startsWith("charset=",true) && it.substringAfter('=').trim().trim('"').lowercase() !in listOf("utf-8","utf8") },"UNSUPPORTED_FORM_CHARSET")
                need(headers(raw).none { it.first in setOf("content-encoding","transfer-encoding") && it.second.lowercase()!="identity" },"ENCODED_BODY_UNSUPPORTED")
                val body=raw.substringAfter("\r\n\r\n");need(body.length<=1024*1024,"FORM_BODY_TOO_LARGE")
                val pairs=body.split('&').filter { it.isNotEmpty() }.map { part -> formPart(part.substringBefore('=')) to formPart(part.substringAfter('=',"")) }
                JsonPrimitive(one(pairs.filter { it.first==ref.s("name") }.map { it.second }))
            }
            "cookie","setCookie" -> {
                need(side==if(field=="cookie") "request" else "response","INVALID_COOKIE_SIDE")
                val values=headers(raw).filter { it.first==if(field=="cookie") "cookie" else "set-cookie" }.flatMap { (_,v) ->
                    (if(field=="cookie") v.split(';') else listOf(v.substringBefore(';'))).map { it.trim() }
                }.filter { it.substringBefore('=')==ref.s("name") && it.contains('=') }.map { it.substringAfter('=') }
                val cookie=one(values);need(cookie.isNotEmpty() && cookie!="\"\"","EMPTY_COOKIE");JsonPrimitive(cookie)
            }
            "json" -> {
                val split=raw.indexOf("\r\n\r\n");need(split>=0,"HTTP_BODY_MISSING")
                need(headers(raw).none { it.first in setOf("content-encoding","transfer-encoding") && it.second.lowercase()!="identity" },"ENCODED_BODY_UNSUPPORTED")
                var body=raw.substring(split+4)
                when(ref.s("bodyEncoding") ?: "TEXT") {
                    "TEXT" -> Unit
                    "UTF8_FROM_LATIN1" -> {
                        need(body.all { it.code<=255 },"INVALID_LATIN1_BODY")
                        val bytes=body.toByteArray(Charsets.ISO_8859_1);body=bytes.toString(Charsets.UTF_8)
                        need(body.toByteArray(Charsets.UTF_8).contentEquals(bytes),"INVALID_UTF8_BODY")
                    }
                    else -> throw Uncertain("INVALID_BODY_ENCODING")
                }
                var node=strict(body)
                val pointer=ref.s("pointer") ?: throw Uncertain("JSON_POINTER_REQUIRED")
                need(pointer.isEmpty() || pointer.startsWith('/'),"INVALID_JSON_POINTER")
                if(pointer.isNotEmpty()) pointer.drop(1).split('/').forEach { part ->
                    need(!Regex("~(?![01])").containsMatchIn(part),"INVALID_JSON_POINTER")
                    val key=part.replace("~1","/").replace("~0","~")
                    node=when(val current=node) {
                        is JsonObject -> current[key]
                        is JsonArray -> if(key.matches(Regex("0|[1-9][0-9]*"))) key.toIntOrNull()?.let { current.getOrNull(it) } else null
                        else -> null
                    } ?: throw Uncertain("JSON_VALUE_MISSING")
                };node
            }
            else -> throw Uncertain("INVALID_FIELD")
        }
        return result to row
    }
    fun review(plan:JsonObject, flows:JsonArray):JsonObject {
        val stages=array(plan["stages"]).map(::obj);val checks=array(plan["checks"]).map(::obj)
        require(stages.size in 1..100 && checks.size in 1..200 && flows.size<=1000) { "REVIEW_LIMIT_EXCEEDED" }
        fun safeId(id:String?)=id!=null && id.matches(Regex("[A-Za-z0-9_-]{1,80}"))
        require(stages.all { safeId(it.s("id")) } && stages.map { it.s("id") }.distinct().size==stages.size) { "INVALID_STAGE_IDS" }
        require(checks.all { safeId(it.s("id")) && it.s("category") in categories } && checks.map { it.s("id") }.distinct().size==checks.size) { "INVALID_CHECK_IDS_OR_CATEGORIES" }
        val expected=plan["expectedFlows"]?.jsonPrimitive?.intOrNull
        require(expected!=null && expected in 1..1000) { "EXPECTED_FLOWS_REQUIRED" }
        val service=obj(plan["httpService"])
        require(!service.s("host").isNullOrBlank() && service["port"]?.jsonPrimitive?.intOrNull in 1..65535 && service["secure"]?.jsonPrimitive?.booleanOrNull!=null) { "HTTP_SERVICE_REQUIRED" }
        val ids=flows.map { obj(it).s("id") };require(ids.all(::safeId) && ids.distinct().size==ids.size) { "INVALID_FLOW_IDS" }
        // The same wire record cannot prove multiple independent repetitions.
        val owners=mutableMapOf<Pair<String?,JsonElement?>,MutableSet<String>>()
        flows.forEach { flow -> val f=obj(flow);array(f["entries"]).map(::obj).forEach { row -> owners.getOrPut(row.s("captureId") to row["id"]) { mutableSetOf() }.add(f.s("id")!!) } }
        val reused=owners.filterValues { it.size>1 }.keys
        val flowReports=flows.map { flow ->
            val f=obj(flow);val groups=array(f["entries"]).map(::obj).groupBy { it.s("captureId") to it["id"] }
            val conflicts=mutableSetOf<Pair<String?,JsonElement?>>()
            val rows=groups.map { (key,versions) ->
                val requests=versions.map { listOf(it["request"],it["httpService"],it["tool"],it["requestTime"]) }.distinct()
                val responses=versions.filter { it.s("responseState")=="RESPONSE_RECEIVED" && it["response"]!=JsonNull && it["response"]!=null }
                if(key.first.isNullOrBlank() || key.second?.jsonPrimitive?.longOrNull==null || requests.size!=1 || responses.map { it["response"] }.distinct().size>1) conflicts.add(key)
                responses.firstOrNull() ?: versions.first()
            }
            val selected=stages.associate { stage ->
                require(stage.s("method")!=null && stage.s("path")?.startsWith('/')==true && stage.s("tool")!=null) { "STAGE_SELECTOR_REQUIRED" }
                val matches=rows.filter { row ->
                    val line=row.s("request")?.substringBefore("\r\n")?.split(' ') ?: emptyList()
                    row["httpService"]==service && line.getOrNull(0)==stage.s("method") && line.getOrNull(1)==stage.s("path") && row.s("tool")==stage.s("tool")
                }.sortedBy { it["id"]?.jsonPrimitive?.longOrNull }
                val occurrence=stage["occurrence"]?.jsonPrimitive?.intOrNull
                require(occurrence==null || occurrence>=1) { "INVALID_OCCURRENCE" }
                val chosen=if(occurrence==null) matches.singleOrNull() else matches.getOrNull(occurrence-1)
                stage.s("id")!! to chosen?.takeUnless { (it.s("captureId") to it["id"]) in conflicts || (it.s("captureId") to it["id"]) in reused }
            }
            val stageRows=selected.values.filterNotNull()
            val selectedKeys=stageRows.map { it.s("captureId") to it["id"] }.toSet()
            val unexpected=rows.filter { it["httpService"]==service && it.s("tool") in stages.map { s -> s.s("tool") } && (it.s("captureId") to it["id"]) !in selectedKeys }
            val orderOk=stageRows.size==stages.size && stageRows.map { it.s("captureId") }.distinct().size==1 &&
                stageRows.zipWithNext().all { (a,b) -> a["id"]!!.jsonPrimitive.long < b["id"]!!.jsonPrimitive.long }
            val results=checks.map { check ->
                var state="INDETERMINATE";var reason="STAGE_ORDER_OR_EVIDENCE_UNRESOLVED"
                if(orderOk) try {
                    val (left,leftRow)=value(obj(check["left"]),selected)
                    val op=check.s("op") ?: "equals"
                    val rightRef=check["right"] as? JsonObject
                    val equal=if(op=="present") left!=JsonNull && left!=JsonPrimitive("") else {
                        need((rightRef!=null) xor check.containsKey("expected"),"ONE_COMPARISON_SOURCE_REQUIRED")
                        val right=rightRef?.let { value(it,selected) }
                        if(right!=null) need(leftRow["httpService"]==right.second["httpService"],"CROSS_SERVICE_COMPARISON")
                        left==(right?.first ?: check.getValue("expected"))
                    }
                    need(op in listOf("equals","notEquals","present"),"INVALID_OPERATION")
                    val pass=if(op=="notEquals") !equal else equal
                    state=if(pass) "PASS" else "FAIL";reason=if(pass) "CONDITION_MATCHED" else "CONDITION_MISMATCH"
                } catch(e:Uncertain) { reason=e.reason } catch(_:Exception) { reason="UNREADABLE_EVIDENCE" }
                buildJsonObject { put("id",check.s("id")!!);put("category",check.s("category")!!);put("state",state);put("reason",reason) }
            }
            buildJsonObject {
                put("id",f.s("id")!!);put("stageOrderVerified",orderOk);put("uniqueEntries",rows.size);put("conflictingEntries",conflicts.size)
                put("unexpectedEntries",JsonArray(unexpected.map { buildJsonObject { put("captureId",it["captureId"] ?: JsonNull);put("id",it["id"] ?: JsonNull) } }))
                put("stages",buildJsonObject { selected.forEach { (id,row) -> put(id,row?.let { buildJsonObject { put("captureId",it["captureId"]!!);put("id",it["id"]!!) } } ?: JsonNull) } })
                put("checks",JsonArray(results))
            }
        }
        val all=flowReports.flatMap { it["checks"]!!.jsonArray }.map(::obj)
        val countMatches=flows.size==expected
        fun state(items:List<JsonObject>)=when { items.any { it.s("state")=="FAIL" } -> "FAIL";items.isEmpty() || items.any { it.s("state")!="PASS" } -> "INDETERMINATE";else -> "PASS" }
        val summaries=categories.associateWith { category -> state(all.filter { it.s("category")==category }) }
        val reviewState=when { summaries.values.any { it=="FAIL" } -> "FAIL";!countMatches || flowReports.any { it["unexpectedEntries"]!!.jsonArray.isNotEmpty() } || summaries.values.any { it!="PASS" } -> "INDETERMINATE";else -> "PASS" }
        return buildJsonObject {
            put("reviewPlanDigest",fingerprint(plan));put("reviewEvidenceDigest",fingerprint(flows))
            put("schemaVersion",1);put("reviewState",reviewState);put("expectedFlows",expected);put("observedFlows",flows.size);put("flowCountMatches",countMatches)
            put("categories",buildJsonObject { summaries.forEach { (k,v) -> put(k,v) } });put("flows",JsonArray(flowReports))
            put("assertionsPassed",all.count { it.s("state")=="PASS" });put("assertionsFailed",all.count { it.s("state")=="FAIL" });put("assertionsIndeterminate",all.count { it.s("state")=="INDETERMINATE" })
            put("semanticReviewRequired",true);put("diagnosisCompleted",false)
            RateLimitObservations.summarize(flows)?.let { put("rateLimitObservations",it) }
        }
    }
}

internal fun Server.registerWorkflowEvidenceReview(service:DiagnosticJobService) {
    mcpTool<ReviewWorkflowEvidence>("""Read-only aggregation of existing workflow evidence. Sends no HTTP, changes no configuration/approvals/execution state and never controls or starts an audit. Supply exactly one of executionId (saved repeated preparation probes only; review preparationOnce evidence separately through diagnostic_job validation) or evidenceJson={flows:[{id,entries:[existing Logger rows]}]}. Rows retain captureId,id,tool,httpService,request,response,responseState,requestTime,responseTime; preserve raw records and include every workflow. executionId reads ALL saved probes, not a page or live Logger. planJson={expectedFlows:positive integer,httpService:{host,port,secure},stages:[{id,method,path,tool,occurrence?:positive integer}],checks:[{id,category,left:{stage,side,field,name?,pointer?,bodyEncoding?},op?:equals|notEquals|present,right?:same reference shape,expected?:JSON value}]}. Paths are exact origin-form including query; tools are exact recorded tool names. Stages must appear in declared strict order in one capture per flow. Repeated endpoints require explicit 1-based occurrence; ambiguity is indeterminate. Categories: AUTHENTICATION,CSRF,SESSION_LOGOUT,INPUT_PRESERVATION,ATTRIBUTE_RESTORATION. Fields: status(response integer),header(name),cookie(request,name),setCookie(response,name),form(name; UTF8 application/x-www-form-urlencoded with duplicate names indeterminate),json(RFC6901 pointer; empty=root). bodyEncoding defaults TEXT; explicitly use UTF8_FROM_LATIN1 only for observed Latin1 rendering of UTF8 wire bytes. Encoded/chunked JSON bodies are unsupported. equals/notEquals require exactly one right reference or expected literal. present checks nonnull/nonempty. Compare authentication identity/status, CSRF sources, newly issued SID to Logout Cookie and same-SID invalidation, exact protected inputs and baseline attributes via separate explicit checks; HTTP200 alone is insufficient. Observed application behavior determines expectations; no site-specific identifiers or success rules are invented. Overlap rows merge by captureId/id only when immutable requests and received responses agree. Missing/unobserved/conflicting evidence is INDETERMINATE. Unconfigured categories, flow-count mismatch and unselected same-service/same-tool entries prevent overall PASS; unrelated tools are retained separately. JSON bodies are limited to 1MiB. Plan and evidence digests identify reviewed inputs, not archive authenticity. PASS means only all supplied conditions matched, not complete semantic review, settings restoration, session cleanup or diagnostic success. Output includes stage evidence IDs and reasons, never compared raw values, bodies, URLs or secrets; input can contain credentials and should remain local. When received 429 evidence exists, optional rateLimitObservations counts unique unambiguous received 429 rows across all supplied flow entries and exposes evidence IDs. Later 2xx/3xx candidates must share capture, service, method, exact origin-path and tool, with increasing IDs and a timestamp-verified request after the 429 response. Missing/conflicting timestamps leave that association unknown. These observations never prove application/authentication recovery, automatic backoff or retry of the same failed check, and do not change reviewState. executionId may also return Default resource-pool fields from the saved compiled plan; that source is historical approved configuration, not verified current/native Task assignment. evidenceJson supplies no pool configuration. Bounds:16MiB per JSON input,1000 flows,100 stages,200 checks. Existing human review, five-run validation and execution digest remain mandatory. This tool never fetches replacement evidence or retries requests.""" + RATE_LIMIT_OBSERVATION_GUIDANCE) {
        require((executionId!=null) xor (evidenceJson!=null)) { "ONE_EVIDENCE_SOURCE_REQUIRED" }
        try {
            val flows=if(executionId!=null) service.savedReviewFlows(executionId) else WorkflowEvidenceReview.parse(evidenceJson!!)["flows"] as? JsonArray ?: error("FLOWS_REQUIRED")
            val report=WorkflowEvidenceReview.review(WorkflowEvidenceReview.parse(planJson),flows)
            val observations=report["rateLimitObservations"] as? JsonObject
            if(executionId!=null && observations!=null) JsonObject(report+("rateLimitObservations" to JsonObject(observations+mapOf(
                "configurationSource" to JsonPrimitive("SAVED_COMPILED_PLAN_DEFAULT_POOLS"),
                "defaultPoolConfigurations" to service.savedRateLimitConfigurations(executionId)
            )))).toString() else report.toString()
        } catch(_:Exception) { throw IllegalArgumentException("EVIDENCE_REVIEW_INPUT_INVALID_OR_UNAVAILABLE") }
    }
}
