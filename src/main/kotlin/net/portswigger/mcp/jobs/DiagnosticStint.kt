package net.portswigger.mcp.jobs

import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import net.portswigger.diagnosis.runner.*
import net.portswigger.mcp.tools.mcpTool
import java.util.concurrent.Executor

@Serializable data class DiagnosticStint(val action:String,val stintId:String,val executionIds:List<String> = emptyList(),
    val size:Int=100,val manifestDigest:String?=null,val previousId:String?=null,val reason:String?=null)

class PreparationStints(private val worker:GuardedWorker,private val store:JobStore,private val executor:Executor) {
    private val pending=mutableSetOf<String>()
    private fun key(id:String)="hw-stint:$id"
    private fun load(id:String)=store.get(key(id))?.jsonObject ?: throw JobRejected("STINT_NOT_FOUND")

    private fun item(id:String,attempt:Int):JsonObject {
        requireJob(id.matches(Regex("[A-Za-z0-9_-]{1,100}")),"INVALID_EXECUTION_ID")
        val r=worker.record(id)
        requireJob(r.epoch==worker.epoch && r.state=="STATIC_VALIDATED","STATIC_VALIDATED_REQUIRED")
        val p=worker.plan(id)
        return buildJsonObject {
            put("executionId",id);put("jobId",p.proposal.jobId);put("revision",p.proposal.revision)
            put("planDigest",p.planDigest);put("attempt",attempt)
        }
    }

    private fun persist(id:String,body:JsonObject):JsonObject {
        val digest=fingerprint(body)
        val manifest=JsonObject(body+("manifestDigest" to JsonPrimitive(digest)))
        store.transaction {
            store.put("hw-manifest:$digest",manifest);store.put(key(id),manifest)
            body.getValue("items").jsonArray.forEach {
                store.put("hw-member:"+it.jsonObject.getValue("executionId").jsonPrimitive.content,JsonPrimitive(id))
            }
        }
        return manifest
    }

    @Synchronized fun checkJobAction(executionId:String,action:String) {
        val id=store.get("hw-member:$executionId")?.jsonPrimitive?.content ?: return
        if(action in setOf("execute","advance","renew_continuation")) throw JobRejected("STINT_PREPARATION_ONLY")
        if(action!="prepare") return
        val items=load(id).getValue("items").jsonArray.map { it.jsonObject }.filter { it["hold"]==null }
        val position=items.indexOfFirst { it["executionId"]==JsonPrimitive(executionId) }
        requireJob(position>=0,"STINT_MEMBER_SUPERSEDED_OR_HELD")
        requireJob(items.take(position).all { worker.record(it.getValue("executionId").jsonPrimitive.content).state=="VALIDATED" },
            "STINT_PREDECESSOR_UNRESOLVED")
        requireJob(worker.record(executionId).state in setOf("PREPARATION_APPROVED","VALIDATED"),"STINT_REVIEW_REQUIRED")
    }
    @Synchronized fun call(input:DiagnosticStint):JsonObject {
        val id=input.stintId
        requireJob(id.matches(Regex("[A-Za-z0-9_-]{1,100}")),"INVALID_STINT_ID")
        val ids=input.executionIds
        if(input.action=="create") {
            requireJob(input.size>0 && ids.size in 1..input.size && ids.distinct().size==ids.size,"INVALID_STINT_SIZE_OR_ITEMS")
            store.get(key(id))?.let {
                val original=store.get("hw-original:$id")
                requireJob(original==jobJson.encodeToJsonElement(input),"STINT_ID_REUSED")
                return it.jsonObject
            }
            val items=ids.map { execution ->
                requireJob(store.get("hw-member:$execution")==null,"STINT_MEMBER_REUSED")
                item(execution,1)
            }
            requireJob(items.distinctBy { it["jobId"] }.size==items.size,"DUPLICATE_STINT_JOB")
            return synchronized(worker) { store.transaction {
                ids.forEach { item(it,1) }
                store.put("hw-original:$id",jobJson.encodeToJsonElement(input))
                persist(id,buildJsonObject { put("stintId",id);put("size",input.size);put("items",JsonArray(items)) })
            }
            }
        }
        val manifest=load(id)
        val digest=manifest.getValue("manifestDigest").jsonPrimitive.content
        val items=manifest.getValue("items").jsonArray.map { it.jsonObject }
        fun execution(row:JsonObject)=row.getValue("executionId").jsonPrimitive.content
        if(input.action=="status") return buildJsonObject {
            put("manifest",manifest)
            put("items",JsonArray(items.map { row -> buildJsonObject {
                val execution=execution(row)
                put("executionId",execution);put("state",worker.record(execution).state)
                if(worker.record(execution).state=="VALIDATED") put("validationDigest",fingerprint(worker.validation(execution)))
            } }))
            store.get("hw-request:$id")?.let { request ->
                val token=request.jsonObject.getValue("reviewDigest").jsonPrimitive.content
                put("reviewRequest",request)
                val receipt=store.get("hw-review:$token")
                if(receipt!=null) put("receipt",receipt)
                put("reviewState",when { receipt!=null -> "APPROVED"; id in pending -> "AWAITING_HUMAN"
                    else -> request.jsonObject["error"]?.jsonPrimitive?.content ?: "INTERRUPTED" })
            }
        }
        requireJob(digest==input.manifestDigest,"STINT_MANIFEST_CHANGED")
        requireJob(id !in pending,"STINT_REVIEW_PENDING")
        if(input.action in setOf("revise","hold")) {
            val old=items.singleOrNull { execution(it)==input.previousId } ?: throw JobRejected("STINT_MEMBER_REQUIRED")
            requireJob(!input.reason.isNullOrBlank() && old["hold"]==null,"STINT_REASON_OR_ACTIVE_ITEM_REQUIRED")
            requireJob(worker.contextStatus()["ownerExecutionId"]==JsonNull,"BURP_CONTEXT_BUSY")
            val attempt=old.getValue("attempt").jsonPrimitive.int
            val replacement=if(input.action=="hold" || attempt>=11) {
                JsonObject(old+("hold" to JsonPrimitive(input.reason)))
            } else {
                val newId=ids.singleOrNull() ?: throw JobRejected("ONE_REVISED_EXECUTION_REQUIRED")
                requireJob(store.get("hw-member:$newId")==null,"STINT_MEMBER_REUSED")
                item(newId,attempt+1).also {
                    requireJob(it["jobId"]==old["jobId"] && it.getValue("revision").jsonPrimitive.int>old.getValue("revision").jsonPrimitive.int,"STINT_REVISION_REQUIRED")
                }
            }
            return synchronized(worker) { store.transaction {
                requireJob(worker.contextStatus()["ownerExecutionId"]==JsonNull,"BURP_CONTEXT_BUSY")
                if(replacement["hold"]==null) item(execution(replacement),attempt+1)
                worker.revoke(execution(old))
                persist(id,JsonObject(manifest-"manifestDigest"+mapOf("previousManifest" to JsonPrimitive(digest),
                "changeReason" to JsonPrimitive(input.reason),"items" to JsonArray(items.map { if(it==old) replacement else it }))))
            } }
        }
        requireJob(input.action in setOf("review_preparation","review_final"),"UNSUPPORTED_STINT_ACTION")
        val selected=items.filter { it["hold"]==null && execution(it) in ids }.map(::execution)
        requireJob(selected.isNotEmpty() && selected==ids,"ORDERED_STINT_SELECTION_REQUIRED")
        val finalReview=input.action=="review_final"
        if(finalReview) requireJob(selected==items.filter { it["hold"]==null }.map(::execution),"FINAL_SELECTION_INCOMPLETE")
        val request=buildJsonObject {
            put("manifestDigest",digest);put("action",input.action);put("executionIds",jobJson.encodeToJsonElement(ids))
            if(finalReview) put("validationDigests",JsonArray(ids.map { JsonPrimitive(fingerprint(worker.validation(it))) }))
        }
        val token=fingerprint(request)
        val record=JsonObject(request+("reviewDigest" to JsonPrimitive(token)))
        store.put("hw-request:$id",record)
        store.get("hw-review:$token")?.let { return it.jsonObject }
        pending.add(id)
        executor.execute {
            try { worker.reviewStint(id,ids,finalReview,digest,token) }
            catch(e:Exception) { store.put("hw-request:$id",JsonObject(record+("error" to JsonPrimitive((e as? JobRejected)?.code ?: e.javaClass.simpleName)))) }
            finally { synchronized(this) { pending.remove(id) } }
        }
        return record
    }
}

fun Server.registerPreparationStintTool(stints:PreparationStints) {
    mcpTool<DiagnosticStint>("""Optional -hw preparation mode for an ordered stint in REVIEW. First use observed requests to author Macro/CPH/Session Handling Rule proposals, then diagnostic_job propose per unique executionId and wait for STATIC_VALIDATED. Use create with stintId, executionIds in requested order, size (default 100, positive). One jobId per target; variants share one slot. Ordinary -re jobs do not need a stint. status returns the current immutable manifest and member states. Supply its manifestDigest for every review or change. review_preparation takes an ordered selection of executionIds and opens ONE Burp human review over the exact plans and endpoints. Poll status for approval, failure or interruption. For approved members use diagnostic_job prepare individually in order, polling the same operation, verifying settings restoration and reviewing all validation pages including one-time evidence. Never repeat a mutation of unknown outcome. After recovery, revise with previousId, reason and one newly proposed executionId for the same jobId and higher revision; obtain fresh preparation approval for that member. Maximum ten corrections after the initial attempt; the next revision request records a hold. Explicit hold requires previousId and reason. review_final takes all non-held members in order after evidence review and records the human decision and validation digests only. It does not issue a scanner execution token or start an audit. Approval receipt refers to the reviewed manifest and ordered selection. Review stale/conflicting settings or credentials before proceeding.""") { stints.call(this).toString() }
}
