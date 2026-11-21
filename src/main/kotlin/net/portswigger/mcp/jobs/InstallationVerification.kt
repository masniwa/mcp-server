package net.portswigger.mcp.jobs

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import net.portswigger.diagnosis.runner.*
import java.nio.file.Path

/** Bootstrap authority is private to a generated loopback plan, never added to the ordinary port. */
class InstallationVerification(private val port:BurpExecutionPort,private val store:JobStore,
    private val approver:HumanApprover,private val profile:Path,
    private val cphConfig:(String,String,Int,String,String)->JsonObject,
    private val pause:()->Unit = { Thread.sleep(2000) }) {
    private val caps=setOf("EXCLUSIVE_CONTEXT","SCANNER_WORKFLOW","DYNAMIC_WORKFLOW_VERIFIED")
    private val localPort=object:BurpExecutionPort by port,EvidenceStreamingPort {
        override fun collectTo(auditId:String,payloadRunId:String?,save:(String,JsonElement)->JsonElement):JsonObject =
            if(port is EvidenceStreamingPort) port.collectTo(auditId,payloadRunId,save) else port.collect(auditId,payloadRunId)
        override fun snapshot()=port.snapshot().let { it.copy(capabilities=it.capabilities+caps) }
        private fun physicalExpected(expected:BurpSnapshot):BurpSnapshot {
            val physical=port.snapshot()
            requireJob(fingerprint(physical.copy(capabilities=physical.capabilities+caps))==fingerprint(expected),"CURRENT_CONTEXT_CHANGED")
            // Adapt only private bootstrap authority. Reviewed settings/identity never refresh from current state.
            return expected.copy(capabilities=physical.capabilities)
        }
        override fun apply(variant:CompiledVariant,expected:BurpSnapshot,operationId:String) {
            port.apply(variant,physicalExpected(expected),operationId)
        }
        override fun restore(baseline:BurpSnapshot,ownedCphNames:Set<String>,expected:BurpSnapshot,operationId:String) {
            val physical=physicalExpected(expected)
            port.restore(baseline.copy(capabilities=physical.capabilities),ownedCphNames,physical,operationId)
        }
    }
    private val worker=GuardedWorker(localPort,store,approver)
    val epoch:String get()=worker.epoch

    fun owns(id:String)=store.get("installation-plan:$id")!=null
    fun recover(id:String,ref:String):ExecutionRecord {
        val marker=store.get("installation-plan:$id")?.jsonPrimitive?.content ?: throw JobRejected("NOT_INSTALLATION_PLAN")
        requireJob(worker.plan(id).planDigest==marker,"INSTALLATION_PLAN_CHANGED")
        return worker.recover(id,ref)
    }
    fun run(id:String,dynamic:Boolean):JsonObject {
        requireJob(id.matches(Regex("[A-Za-z0-9_-]{1,80}")),"INVALID_EXECUTION_ID")
        requireJob(!owns(id) && store.get("execution:$id")==null,"EXECUTION_ID_REUSED")
        requireJob(worker.contextStatus()["ownerExecutionId"]==JsonNull,"BURP_CONTEXT_BUSY")
        val actor=approver.reviewInstallation("検証ID: $id\nこのPC内の一時HTTPサーバー(127.0.0.1の自動割当ポート)だけを対象に、"+
            (if(dynamic) "CPHの毎回変化する一回限りtokenの取得・置換とScanner" else "Scanner")+
            "を検証します。準備とScanはそれぞれ別途REVIEW承認が必要です。既存の他Taskが動作していないことをDashboardで確認してください。")
            ?: throw JobRejected("HUMAN_DENIED")
        requireJob(actor.isNotBlank(),"APPROVER_REQUIRED")
        worker.verifyExclusiveContext()
        CapabilityFixture().use { fixture ->
            // Reserve the shared context before the first observed request. Never hold a DB transaction over HTTP.
            store.transaction {
                requireJob(worker.contextStatus()["ownerExecutionId"]==JsonNull,"BURP_CONTEXT_BUSY")
                store.put("active",JsonPrimitive(id))
            }
            val proposal=try {
                store.onceJson("$id:installation-observation","local-fixture-v1:$dynamic") {
                    jobJson.encodeToJsonElement(proposal(id,fixture,dynamic))
                }.let { jobJson.decodeFromJsonElement<JobProposal>(it) }
            } finally {
                store.transaction {
                    if(store.get("active")==JsonPrimitive(id)) store.put("active",JsonNull)
                }
            }
            val plan=worker.register(id,proposal)
            store.put("installation-plan:$id",JsonPrimitive(plan.planDigest))
            worker.approve(id,ApprovalStage.PREPARATION)
            val validation=worker.prepare(id)
            requireJob(validation.restored && validation.probes.size==5 && validation.probes.all {
                it.response.substringBefore("\r\n").contains(" 200 ")
            },"INSTALLATION_PREPARATION_FAILED")
            // A fixed, single target has no speculative next target. Retain the same planning declaration.
            LookAheadPlanner(worker,store,JobDrafts(worker,store)).use { it.declare(id,"[]") }
            worker.approve(id,ApprovalStage.EXECUTION)
            val r=worker.record(id)
            var execution=worker.start(id,r.fence,r.epoch)
            val deadline=System.nanoTime()+java.util.concurrent.TimeUnit.MINUTES.toNanos(15)
            while(execution.state in setOf("RUNNING","OBSERVATION_UNKNOWN") && System.nanoTime()<deadline) {
                pause();execution=worker.poll(id)
            }
            requireJob(execution.state=="EXECUTION_FINISHED" && execution.evidenceState=="COLLECTED","INSTALLATION_EXECUTION_INCOMPLETE")
            val saved=worker.committedResults(id)
            val records=saved.getValue("records").jsonArray
            val audit=records.firstNotNullOfOrNull { it.jsonObject["auditId"]?.jsonPrimitive?.contentOrNull }
                ?: throw JobRejected("INSTALLATION_AUDIT_REQUIRED")
            requireJob(records.any { it.jsonObject["response"]?.jsonPrimitive?.contentOrNull?.substringBefore("\r\n")?.contains(" 200 ")==true },
                "INSTALLATION_NORMAL_CONTROL_FAILED")
            verifyScannerEvidence(saved,fixture.baseUri().port,fixture.baseUri().path,dynamic) { record -> worker.evidencePages(record,"loggerPages") }
            requireJob(!dynamic || fixture.acceptedChallenges()>=7,"INSTALLATION_DYNAMIC_FLOW_NOT_VERIFIED")
            val evidence=buildJsonObject {
                put("capability",if(dynamic) "DYNAMIC_WORKFLOW_VERIFIED" else "SCANNER_WORKFLOW")
                put("executionId",id);put("auditId",audit);put("planDigest",plan.planDigest)
                put("validationDigest",fingerprint(validation));put("resultsDigest",fingerprint(saved))
                put("workerEpoch",worker.epoch);put("verifiedAt",java.time.Instant.now().epochSecond)
                put("restored",true);put("initialOperator",actor)
            }
            store.put("setup-evidence:$id",evidence)
            val registration=approver.reviewInstallation("検証ID: $id\nAudit: $audit\n"+
                "5回の正常検証、SCANNER起点の実通信、保存結果、設定復元を確認しました。"+
                "${evidence["capability"]}と排他制御を、このPCの設定へ登録します。\n"+
                "これはローカルfixtureの検証です。実対象の認証・Macro・業務状態の検証は各ジョブで必要です。")
                ?: throw JobRejected("HUMAN_DENIED")
            requireJob(registration.isNotBlank(),"APPROVER_REQUIRED")
            val profileWriter=InstallationProfile(profile)
            val exclusive=worker.verifyExclusiveContext()
            profileWriter.register(JsonObject(exclusive+("operator" to JsonPrimitive(registration))))
            // Dynamic verification also exercises the complete ordinary Scanner lifecycle.
            if(dynamic) profileWriter.register(JsonObject(evidence+mapOf("capability" to JsonPrimitive("SCANNER_WORKFLOW"),"operator" to JsonPrimitive(registration))))
            return profileWriter.register(JsonObject(evidence+("operator" to JsonPrimitive(registration))))
        }
    }

    private fun proposal(id:String,fixture:CapabilityFixture,dynamic:Boolean):JobProposal {
        val base=fixture.baseUri();val root=Endpoint("http","127.0.0.1",base.port,base.path)
        fun observe(name:String,path:String,method:String="GET",headers:String=""):HttpMaterial {
            val e=root.copy(path=base.path+path)
            val raw="$method ${e.path} HTTP/1.1\r\nHost: 127.0.0.1:${e.port}\r\n${headers}Content-Length: 0\r\nConnection: close\r\n\r\n"
            val response=port.oncePreparation(RequestPlan(e,raw,name,digest(raw))).first
            return HttpMaterial(name,e,raw,response,digest(raw),digest(response))
        }
        val source=if(dynamic) observe("source","issue") else null
        val target=if(dynamic) observe("target","verify?q=baseline","POST",
            "X-cphtarget: cphtarget:setup\r\nX-Fixture-Token: {{setup_token}}\r\n")
            else observe("target","issue?q=baseline")
        val scope=buildJsonObject {
            put("advanced_mode",false)
            putJsonArray("include") { add(buildJsonObject {
                put("enabled",true);put("include_subdomains",false);put("prefix",root.url())
            }) }
            put("exclude",JsonArray(emptyList()))
        }
        val settings=if(source==null) SettingsPlan(targetScope=scope) else {
            val config=cphConfig("job:$id:token",source.request,base.port,source.response,"cphtarget:setup")
            SettingsPlan(cph=config,cphOrder=config.keys.toList(),serialScannerRequests=true,targetScope=scope)
        }
        val selectors=buildJsonObject { putJsonArray("insertionPointParameters") {
            add(buildJsonObject { put("name","q");put("type","URL") })
        } }
        return JobProposal(jobId=id.take(80),revision=1,objective="Local installation verification only",
            targetPolicy=listOf(TargetPermit(root,true)),materials=listOfNotNull(source,target),
            session=SessionPlan(false,"OMIT","Isolated generated loopback fixture","installation-fixture"),
            variants=listOf(ScanVariant("reflection","REFLECTION",request=RequestPlan(target.endpoint,target.request,target.id,target.requestSha256,selectors),settings=settings)),
            requiredCapabilities=if(dynamic) caps else caps-"DYNAMIC_WORKFLOW_VERIFIED",
            cleanupPolicy="Stop fixture after completion; restore native settings; retain disabled owned CPH tabs as evidence",
            requestedInputParameters=listOf(InputParameter("q","URL")))
    }

    companion object {
        @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
        internal fun verifyScannerEvidence(saved:JsonObject,port:Int,prefix:String,dynamic:Boolean,
            pages:((JsonObject)->Sequence<JsonElement>)?=null) {
            val rows=saved.getValue("records").jsonArray.flatMap { record ->
                val values=pages?.invoke(record.jsonObject)?.toList() ?: record.jsonObject["loggerPages"]?.jsonArray.orEmpty()
                values.flatMap { page ->
                    jobJson.decodeToSequence<JsonObject>(page.jsonPrimitive.content.byteInputStream(),DecodeSequenceMode.WHITESPACE_SEPARATED).toList()
                }
            }
            val actual=rows.filter { row ->
                val service=row["httpService"]?.jsonObject
                row["tool"]==JsonPrimitive("SCANNER") && service?.get("host")==JsonPrimitive("127.0.0.1") &&
                    service["port"]==JsonPrimitive(port) && service["secure"]==JsonPrimitive(false) &&
                    row["request"]?.jsonPrimitive?.contentOrNull?.startsWith(if(dynamic) "POST ${prefix}verify?" else "GET ${prefix}issue?")==true &&
                    row["response"]?.jsonPrimitive?.contentOrNull?.substringBefore("\r\n")?.contains(" 200 ")==true
            }
            requireJob(actual.isNotEmpty(),"INSTALLATION_SCANNER_EVIDENCE_REQUIRED")
            if(dynamic) {
                val tokens=actual.mapNotNull { row ->
                    Regex("(?im)^X-Fixture-Token: ([a-f0-9-]{36})\\r?$").find(row.getValue("request").jsonPrimitive.content)?.groupValues?.get(1)
                }.toSet()
                requireJob(tokens.isNotEmpty(),"INSTALLATION_DYNAMIC_WIRE_REQUIRED")
                requireJob(tokens.all { token -> rows.any { row ->
                    row["httpService"]?.jsonObject?.get("host")==JsonPrimitive("127.0.0.1") &&
                        row["httpService"]?.jsonObject?.get("port")==JsonPrimitive(port) &&
                        row["httpService"]?.jsonObject?.get("secure")==JsonPrimitive(false) &&
                        row["request"]?.jsonPrimitive?.contentOrNull?.startsWith("GET ${prefix}issue ")==true &&
                        row["response"]?.jsonPrimitive?.contentOrNull?.substringAfter("\r\n\r\n")==token
                } },"INSTALLATION_DYNAMIC_SOURCE_REQUIRED")
            }
        }
    }
}
