package net.portswigger.diagnosis.runner

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/** Caller authenticates before entering this dispatcher. No arbitrary low-level tool invocation. */
class WorkerProtocol(private val worker:GuardedWorker) {
    fun handle(request:WorkerRequest):WorkerReply = try {
        val id=request.executionId
        val body:JsonElement=when(request.action) {
            "propose" -> jobJson.encodeToJsonElement(worker.register(id,jobJson.decodeFromJsonElement<JobProposal>(request.body)))
            "review_preparation" -> jobJson.encodeToJsonElement(worker.approve(id,ApprovalStage.PREPARATION))
            "prepare" -> jobJson.encodeToJsonElement(worker.prepare(id))
            "review_execution" -> jobJson.encodeToJsonElement(worker.approve(id,ApprovalStage.EXECUTION))
            "renew_continuation" -> jobJson.encodeToJsonElement(worker.renewContinuation(id))
            "start" -> jobJson.encodeToJsonElement(worker.start(id,request.body["fence"]!!.jsonPrimitive.long,request.body["epoch"]!!.jsonPrimitive.content))
            "poll" -> jobJson.encodeToJsonElement(worker.poll(id))
            "recovery_evaluate" -> worker.evaluateRecovery(id)
            "recovery_reconcile" -> jobJson.encodeToJsonElement(worker.reconcileRecovery(id,
                jobJson.decodeFromJsonElement<RecoverySelection>(request.body.getValue("selection")),
                request.body.getValue("evidenceRef").jsonPrimitive.content,
                request.body.getValue("operationId").jsonPrimitive.content))
            "status" -> jobJson.encodeToJsonElement(worker.record(id))
            "validation" -> jobJson.encodeToJsonElement(worker.validation(id))
            "observe" -> worker.observeNative(id) ?: JsonNull
            "results" -> worker.savedResults(id)
            "refresh_results" -> worker.capturePartialResults(id)
            "revoke" -> { worker.revoke(id);jobJson.encodeToJsonElement(worker.record(id)) }
            "reconcile" -> jobJson.encodeToJsonElement(worker.reconcileRestored(id,request.body["evidenceRef"]!!.jsonPrimitive.content))
            "recover" -> jobJson.encodeToJsonElement(worker.recover(id,request.body["evidenceRef"]!!.jsonPrimitive.content))
            else -> throw JobRejected("UNSUPPORTED_WORKER_OPERATION")
        }
        WorkerReply(true,body)
    } catch(e:Exception) { WorkerReply(false,errorCode=(e as? JobRejected)?.code ?: "WORKER_OPERATION_FAILED") }
}

fun interface WorkerConnection { fun call(request:WorkerRequest):WorkerReply }

/** Separate process uses this client. Timeouts never trigger an automatic repeat of a mutating call. */
class HttpWorkerConnection(private val url:URI,private val token:String):WorkerConnection {
    private val http=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).followRedirects(HttpClient.Redirect.NEVER).build()
    init { requireJob(url.scheme=="http" && url.host in setOf("127.0.0.1","localhost") && url.userInfo==null && url.path=="/diagnosis/worker","LOCAL_WORKER_URL_REQUIRED") }
    override fun call(request:WorkerRequest):WorkerReply {
        val req=HttpRequest.newBuilder(url).timeout(Duration.ofMinutes(15)).header("Authorization","Bearer $token")
            .header("Content-Type","application/json").POST(HttpRequest.BodyPublishers.ofString(jobJson.encodeToString(request))).build()
        val response=http.send(req,HttpResponse.BodyHandlers.ofString())
        requireJob(response.statusCode()==200,"WORKER_HTTP_REJECTED")
        return jobJson.decodeFromString(response.body())
    }
}

/** Workflow driver is independent of Codex and Montoya. Human approval remains on the trusted worker UI. */
class JobRunner(private val connection:WorkerConnection,private val store:JobStore) {
    fun call(action:String,id:String,body:JsonObject=JsonObject(emptyMap())):JsonElement {
        // Record the attempt before transport. Connection failures leave an explicit unknown outcome.
        val key="client-attempt:$id:$action:${java.util.UUID.randomUUID()}"
        store.put(key,buildJsonObject { put("action",action);put("state","INTENT") })
        val reply=connection.call(WorkerRequest(action,id,body))
        store.put(key,jobJson.encodeToJsonElement(reply))
        requireJob(reply.success,reply.errorCode ?: "WORKER_FAILED")
        store.put("last:$id",reply.body)
        return reply.body
    }
    fun prepare(id:String,job:JobProposal):JsonElement {
        call("propose",id,jobJson.encodeToJsonElement(job).jsonObject)
        call("review_preparation",id)
        return call("prepare",id)
    }
    fun start(id:String):JsonElement {
        var r=jobJson.decodeFromJsonElement<ExecutionRecord>(call("status",id))
        if(r.state=="VALIDATED") {
            call("review_execution",id)
            r=jobJson.decodeFromJsonElement(call("status",id))
        }
        return call("start",id,buildJsonObject { put("fence",r.fence);put("epoch",r.epoch) })
    }
    fun run(id:String,pause:()->Unit={ Thread.sleep(2000) }):ExecutionRecord {
        var state=jobJson.decodeFromJsonElement<ExecutionRecord>(start(id))
        while(state.state in setOf("RUNNING","OBSERVATION_UNKNOWN","EXECUTION_APPROVED")) {
            if(state.state=="EXECUTION_APPROVED") state=jobJson.decodeFromJsonElement(start(id)) else {
                pause();state=jobJson.decodeFromJsonElement(call("poll",id))
            }
        }
        return state
    }
}
