package net.portswigger.mcp.jobs

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import net.portswigger.diagnosis.runner.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class DiagnosticJobServiceTest {
    @Test fun pagedEvidencePublicContractVerifiesSelectedSourcesWithoutReturningBodies() {
        val (worker,store,_)=startFixture("""{"status":"started","auditId":"native-fixture"}""")
        store.use { DiagnosticJobService(worker,store,false).use { service ->
            val writer=EvidencePageWriter(store,"execution","native-fixture")
            val issue=JsonPrimitive("anonymous-private-issue")
            val ref=writer.save("siteMapIssues",issue)
            val log=writer.save("loggerPages",JsonPrimitive("{\"id\":1}\n{\"id\":2}"))
            val record=buildJsonObject {
                put("evidencePageFormat",EVIDENCE_PAGE_FORMAT);put("siteMapIssues",JsonArray(listOf(ref)))
                put("loggerPages",JsonArray(listOf(log)))
            }
            store.put("saved",record)
            store.put("result-index:execution",JsonArray(listOf(buildJsonObject { put("key","saved");put("digest",fingerprint(record)) })))
            val full=service.call(DiagnosticJob("evidence","execution",evidenceSource="issues",count=1))
            assertEquals(JsonArray(listOf(issue)),full["entries"])
            val metadata=service.call(DiagnosticJob("evidence","execution",evidenceSource="issues",includeWireEvidence=false,count=1))
            assertEquals(JsonPrimitive(fingerprint(issue)),metadata.getValue("entries").jsonArray.single().jsonObject["digest"])
            assertFalse(metadata.toString().contains("anonymous-private-issue"))
            val logger=service.call(DiagnosticJob("evidence","execution",offset=1,count=1))
            assertEquals(JsonPrimitive(2),logger.getValue("entries").jsonArray.single().jsonObject["id"])
            assertEquals(0,startToolCalls.get())
            val encoded=jobJson.encodeToJsonElement(DiagnosticJob("capture","execution")).jsonObject
            assertFalse("evidenceSource" in encoded);assertFalse("includeWireEvidence" in encoded)
        } }
    }
    @Test fun readOnlyCaptureAfterWorkerRestartKeepsNativeIdentityAndNeverResubmits() {
        val (worker,store,port)=startFixture("""{"status":"started","auditId":"native-fixture"}""")
        store.use {
            tryStart(worker)
            val restarted=GuardedWorker(port,store,HumanApprover { _,_,_ -> error("read only") })
            val before=restarted.record("execution")
            restarted.capturePartialResults("execution")
            assertEquals(before,restarted.record("execution"))
            assertEquals(1,startToolCalls.get())
            assertEquals("native-fixture",before.auditId)
        }
    }
    @Test fun statusRetainsHistoricalStorageFailureWithoutTreatingItAsCurrentHealthOrReplaying() {
        val (worker,store,_)=startFixture("""{"status":"started","auditId":"native-fixture"}""")
        tryStart(worker)
        val saved=buildJsonObject { put("errorCode","STORE_SQLITE_FAILURE");putJsonObject("errorDetails") { put("stage","RECORD_WRITE");put("sqlitePrimaryCode","18") } }
        store.put("storage-failure:execution",saved)
        store.use { DiagnosticJobService(worker,store,false).use { service ->
            val status=service.status("execution")
            assertEquals(saved,status["lastStorageFailure"]);assertEquals(JsonPrimitive(false),status["diagnosisCompleted"])
            assertEquals(saved,store.get("storage-failure:execution"));assertEquals(1,startToolCalls.get())
        } }
    }
    @Test fun sqliteOperationFailureExposesSafeNumericCodesWithoutLeakingSqlMessage() {
        val (worker,actual,_)=startFixture("""{"status":"started","auditId":"native-fixture"}""")
        tryStart(worker)
        val failingWorker=io.mockk.spyk(worker)
        io.mockk.every { failingWorker.capturePartialResults("execution") } throws java.sql.SQLException("secret request and SQL text","private-state",18)
        actual.use { DiagnosticJobService(failingWorker,actual,false).use { service ->
            service.call(DiagnosticJob("capture","execution",operationId="sqlite-error"))
            val failed=await(service,"sqlite-error")
            assertEquals(JsonPrimitive("FAILED"),failed["state"])
            assertEquals(JsonPrimitive("STORE_SQLITE_FAILURE"),failed["errorCode"])
            assertEquals(JsonPrimitive("18"),failed["errorDetails"]!!.jsonObject["sqlitePrimaryCode"])
            assertFalse(failed.toString().contains("secret request"));assertFalse(failed.toString().contains("private-state"))
            assertEquals(1,startToolCalls.get())
        } }
    }
    @Test fun legacyStartResultWithoutDigestDoesNotBlockCurrentHandleBasedCleanup() {
        val (worker,store,_)=startFixture("""{"status":"submission_outcome_unknown","auditId":"native-fixture","submissionError":"unknown"}""")
        store.use {
            tryStart(worker)
            java.sql.DriverManager.getConnection("jdbc:sqlite:"+store.directory.resolve("jobs.sqlite").toAbsolutePath()).use { connection ->
                connection.createStatement().use { it.executeUpdate("UPDATE operations SET result_digest=NULL WHERE id='execution:start:0'") }
            }
            assertEquals("native-fixture",worker.record("execution").auditId)
            val evaluation=worker.evaluateRecovery("execution")
            assertFalse(evaluation.getValue("noAuditStartProven").jsonPrimitive.boolean)
            val recovered=worker.reconcileRecovery("execution",RecoverySelection(evaluation.getValue("currentSnapshotDigest").jsonPrimitive.content),"fresh current native and shared stop","legacy-cleanup")
            assertEquals("MAINTENANCE_RESTORED_UNVERIFIED",recovered.state);assertEquals("INCOMPLETE",recovered.diagnosisState)
            assertEquals("OPERATION_RESULT_UNVERIFIABLE",assertThrows(JobRejected::class.java) {
                store.committedOnceResult("execution:start:0",fingerprint(worker.plan("execution").variants.single().variant))
            }.code)
            assertEquals(1,startToolCalls.get());assertEquals(JsonNull,store.get("active"))
        }
    }
    @Test fun publicAcceptanceMetadataIsAtomicBeforeAnyTaskStarts() {
        val (worker,actual,port)=startFixture("{}")
        val store=io.mockk.spyk(actual)
        io.mockk.every { store.put("mcp-last-operation:execution",any<JsonElement>()) } throws java.io.IOException("fixture acceptance write")
        store.use { DiagnosticJobService(worker,store,false).use { service ->
            assertThrows(java.io.IOException::class.java) { service.call(DiagnosticJob("advance","execution",operationId="acceptance")) }
            assertNull(store.get("mcp-operation:acceptance"))
            io.mockk.every { store.put("mcp-last-operation:execution",any<JsonElement>()) } answers { callOriginal() }
            assertEquals(JsonPrimitive("acceptance"),service.call(DiagnosticJob("advance","execution",operationId="acceptance"))["operationId"])
            assertEquals(JsonPrimitive("FAILED"),await(service,"acceptance")["state"])
            assertEquals(0,port.starts.get());assertEquals(0,startToolCalls.get())
        } }
    }
    @Test fun successfulCaptureWithUnpersistedPublicResultRemainsReadableWithoutReplay() {
        val (worker,actual,_)=startFixture("""{"status":"started","auditId":"native-fixture"}""")
        tryStart(worker)
        val store=io.mockk.spyk(actual)
        io.mockk.every { store.put("mcp-operation:capture-result",any<JsonElement>()) } answers {
            if(secondArg<JsonElement>().jsonObject["state"]==JsonPrimitive("SUCCEEDED")) throw java.io.IOException("fixture final save")
            callOriginal()
        }
        store.use {
          var evidence:JsonObject?=null
          DiagnosticJobService(worker,store,false).use { service ->
            service.call(DiagnosticJob("capture","execution",operationId="capture-result"))
            val deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(5)
            var operation=service.call(DiagnosticJob("operation","execution",operationId="capture-result"))
            while(operation["state"]==JsonPrimitive("RUNNING") && System.nanoTime()<deadline) {
                Thread.sleep(10);operation=service.call(DiagnosticJob("operation","execution",operationId="capture-result"))
            }
            assertEquals(JsonPrimitive("OUTCOME_UNKNOWN"),operation["state"])
            assertEquals(JsonPrimitive("SUCCEEDED"),operation["completionStateObserved"])
            assertEquals(JsonPrimitive(false),operation["completionRecordPersisted"])
            evidence=worker.committedResults("execution")
            service.call(DiagnosticJob("capture","execution",operationId="capture-result"))
            assertEquals(evidence,worker.committedResults("execution"));assertEquals(1,startToolCalls.get())
          }
          DiagnosticJobService(worker,store,false).use { restarted ->
            assertEquals(JsonPrimitive("OUTCOME_UNKNOWN"),restarted.call(DiagnosticJob("operation","execution",operationId="capture-result"))["state"])
            restarted.call(DiagnosticJob("capture","execution",operationId="capture-result"))
            assertEquals(evidence,worker.committedResults("execution"));assertEquals(1,startToolCalls.get())
          }
        }
    }
    @Test fun finalPublicOperationWriteFailureDoesNotLeaveAnImaginaryRunningTask() {
        val (worker,actual,port)=startFixture("""{"status":"started","auditId":"native-fixture"}""")
        val store=io.mockk.spyk(actual)
        io.mockk.every { store.put("mcp-operation:lost-result",any<JsonElement>()) } answers {
            val value=secondArg<JsonElement>().jsonObject
            if(value["state"] in setOf(JsonPrimitive("FAILED"),JsonPrimitive("SUCCEEDED"))) throw java.io.IOException("fixture final operation save")
            callOriginal()
        }
        store.use { DiagnosticJobService(worker,store,false).use { service ->
            val beforeProbes=port.probes.get()
            service.call(DiagnosticJob("advance","execution",operationId="lost-result"))
            val deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(5)
            var result=service.call(DiagnosticJob("operation","execution",operationId="lost-result"))
            while(result["state"]==JsonPrimitive("RUNNING") && System.nanoTime()<deadline) {
                Thread.sleep(10);result=service.call(DiagnosticJob("operation","execution",operationId="lost-result"))
            }
            assertEquals(JsonPrimitive("OUTCOME_UNKNOWN"),result["state"])
            assertEquals(JsonPrimitive("IOException"),result["persistenceError"])
            assertEquals(JsonPrimitive("OUTCOME_UNKNOWN"),service.call(DiagnosticJob("advance","execution",operationId="lost-result"))["state"])
            assertEquals(JsonPrimitive("next-observation"),service.call(DiagnosticJob("advance","execution",operationId="next-observation"))["operationId"])
            assertEquals(JsonPrimitive("FAILED"),await(service,"next-observation")["state"])
            assertEquals(beforeProbes,port.probes.get());assertEquals(0,port.starts.get())
        } }
    }
    @Test fun metricMetadataFailureCannotEraseCommittedNativeIdentityOrCounters() {
        val (worker,store,_)=startFixture("""{"status":"started","auditId":"native-fixture","auditRequestCount":4}""","native-known:execution:0")
        store.use {
            assertThrows(java.io.IOException::class.java) { tryStart(worker) }
            assertEquals("RUNNING",worker.record("execution").state);assertEquals("native-fixture",worker.record("execution").auditId)
            DiagnosticJobService(worker,store,false).use { service ->
                val status=service.status("execution")
                assertEquals(JsonPrimitive("native-fixture"),status.getValue("execution").jsonObject["auditId"])
                assertEquals(JsonPrimitive(4),status.getValue("lastKnownNativeMetrics").jsonObject.getValue("auditRequestCount").jsonObject["value"])
            }
            tryStart(worker);assertEquals(1,startToolCalls.get())
        }
    }

    @Test fun committedNativeHandleAndMetricsSurviveSupplementaryMetadataFailure() {
        val (worker,store,_)=startFixture("""{"status":"started","auditId":"native-fixture","auditRequestCount":4,"auditErrorCount":0}""","start-outcome:execution:0")
        store.use {
            assertThrows(java.io.IOException::class.java) { tryStart(worker) }
            assertEquals("RUNNING",worker.record("execution").state)
            assertEquals("native-fixture",worker.record("execution").auditId)
            assertTrue(worker.record("execution").warnings.any { it.startsWith("START_RESULT_METADATA_SAVE_FAILED:") })
            assertEquals(JsonPrimitive(4),worker.lastKnownNativeMetrics("execution").getValue("auditRequestCount").jsonObject["value"])
            assertEquals(JsonNull,worker.lastKnownNativeMetrics("execution").getValue("auditRequestCount").jsonObject["observedAt"])
            assertEquals(JsonPrimitive(false),worker.lastKnownNativeMetrics("execution").getValue("auditRequestCount").jsonObject["currentStopProof"])
            DiagnosticJobService(worker,store,false).use { service ->
                val status=service.status("execution")
                assertEquals(JsonPrimitive("native-fixture"),status.getValue("execution").jsonObject["auditId"])
                assertEquals(JsonPrimitive("COMMITTED_START_RESULT"),status.getValue("startOutcome").jsonObject["source"])
            }
            assertEquals("native-fixture",worker.capturePartialResults("execution").getValue("execution").jsonObject.getValue("auditId").jsonPrimitive.content)
            tryStart(worker)
            io.mockk.every { store.put("start-outcome:execution:0",any<JsonElement>()) } answers { callOriginal() }
            assertEquals("EXECUTION_FINISHED",worker.poll("execution").state)
            assertEquals(1,startToolCalls.get())
        }
    }
    @Test fun metadataLinkageFailurePreservesKnownAcceptanceWithoutRetry() {
        val (worker,store,_)=startFixture("""{"status":"started","auditId":"native-fixture"}""","start-outcome:execution:0",NoSuchMethodError("fixture SDK"))
        store.use {
            assertThrows(NoSuchMethodError::class.java) { tryStart(worker) }
            assertEquals("RUNNING",worker.record("execution").state);assertEquals("native-fixture",worker.record("execution").auditId)
            tryStart(worker);assertEquals(1,startToolCalls.get())
        }
    }
    @Test fun committedNativeIdentifierSurvivesExecutionRecordWriteFailure() {
        val (worker,store,_)=startFixture("""{"status":"started","auditId":"native-fixture","auditRequestCount":4}""","execution:execution")
        store.use {
            assertThrows(java.io.IOException::class.java) { tryStart(worker) }
            assertEquals("SUBMITTING",worker.record("execution").state)
            assertEquals("native-fixture",worker.record("execution").auditId)
            assertNotEquals(JsonNull,worker.startOutcome("execution"))
            assertEquals(JsonPrimitive(4),worker.lastKnownNativeMetrics("execution").getValue("auditRequestCount").jsonObject["value"])
            assertThrows(JobRejected::class.java) { tryStart(worker) };assertEquals(1,startToolCalls.get())
        }
    }
    @Test fun committedStartSurvivesMetadataCrashAndRequiresFreshNativeStopForCleanup() {
        val (worker,store,port)=startFixture("""{"status":"started","auditId":"native-fixture","auditRequestCount":4}""")
        store.use {
            tryStart(worker)
            store.put("execution:execution",jobJson.encodeToJsonElement(worker.record("execution").copy(state="SUBMITTING",auditId=null)))
            store.put("start-outcome:execution:0",JsonNull);store.put("native-known:execution:0",JsonNull)
            val oldRecord=store.get("execution:execution")
            assertEquals("native-fixture",worker.record("execution").auditId)
            assertEquals(JsonNull,worker.startOutcome("execution").jsonObject["observedAt"])
            assertEquals(oldRecord,store.get("execution:execution"))
            port.handlesMissing=true
            var evaluation=worker.evaluateRecovery("execution")
            assertTrue("NATIVE_TERMINATION_UNPROVEN" in evaluation.getValue("blockers").jsonArray.map { it.jsonPrimitive.content })
            assertThrows(JobRejected::class.java) { worker.reconcileRecovery("execution",RecoverySelection(evaluation.getValue("currentSnapshotDigest").jsonPrimitive.content),"missing native stop","missing-stop") }
            port.handlesMissing=false
            evaluation=worker.evaluateRecovery("execution")
            assertEquals("MAINTENANCE_RESTORED_UNVERIFIED",worker.reconcileRecovery("execution",RecoverySelection(evaluation.getValue("currentSnapshotDigest").jsonPrimitive.content),"observed terminal and shared stop","cleanup").state)
            assertEquals(1,startToolCalls.get());assertEquals(JsonNull,store.get("active"))
        }
    }
    @Test fun oldEpochCommittedStartExposesHistoryWithoutInventingNativeHandleOrTermination() {
        val (worker,store,port)=startFixture("""{"status":"started","auditId":"native-fixture","auditRequestCount":4}""")
        store.use {
            tryStart(worker)
            store.put("execution:execution",jobJson.encodeToJsonElement(worker.record("execution").copy(state="SUBMITTING",auditId=null)))
            store.put("start-outcome:execution:0",JsonNull);store.put("native-known:execution:0",JsonNull)
            port.handlesMissing=true
            val restarted=GuardedWorker(port,store,HumanApprover { _,_,_ -> "human" })
            assertEquals("native-fixture",restarted.record("execution").auditId)
            assertEquals(JsonPrimitive(4),restarted.lastKnownNativeMetrics("execution").getValue("auditRequestCount").jsonObject["value"])
            assertThrows(JobRejected::class.java) { restarted.observeNative("execution") }
            val evaluation=restarted.evaluateRecovery("execution")
            assertFalse(evaluation.getValue("noAuditStartProven").jsonPrimitive.boolean)
            assertThrows(JobRejected::class.java) { restarted.reconcileRecovery("execution",RecoverySelection(evaluation.getValue("currentSnapshotDigest").jsonPrimitive.content),"no shutdown evidence","cleanup") }
            assertEquals(1,startToolCalls.get());assertEquals(JsonPrimitive("execution"),store.get("active"))
        }
    }
    @Test fun corruptCommittedStartCannotSupplyMissingIdentifiersOrStopProof() {
        val (worker,store,_)=startFixture("""{"status":"started","auditId":"native-fixture"}""")
        store.use {
            tryStart(worker)
            store.put("execution:execution",jobJson.encodeToJsonElement(worker.record("execution").copy(state="SUBMISSION_UNKNOWN",auditId=null)))
            store.put("start-outcome:execution:0",JsonNull)
            java.sql.DriverManager.getConnection("jdbc:sqlite:"+store.directory.resolve("jobs.sqlite").toAbsolutePath()).use { connection ->
                connection.createStatement().use { it.executeUpdate("UPDATE operations SET result_digest=NULL WHERE id='execution:start:0'") }
            }
            assertNull(worker.record("execution").auditId)
            assertEquals("OPERATION_RESULT_UNVERIFIABLE",assertThrows(JobRejected::class.java) { worker.startOutcome("execution") }.code)
            assertFalse(worker.evaluateRecovery("execution").getValue("noAuditStartProven").jsonPrimitive.boolean)
            assertThrows(JobRejected::class.java) { tryStart(worker) };assertEquals(1,startToolCalls.get())
        }
    }
    @Test fun unknownSubmissionRemainsUnknownWhenSummaryWriteFails() {
        val (worker,store,_)=startFixture("""{"status":"submission_outcome_unknown","auditId":"native-fixture","submissionError":"unknown"}""","start-outcome:execution:0")
        store.use {
            assertThrows(java.io.IOException::class.java) { tryStart(worker) }
            assertEquals("SUBMISSION_UNKNOWN",worker.record("execution").state)
            assertEquals("native-fixture",worker.record("execution").auditId)
            assertEquals("SUBMISSION_UNKNOWN",worker.poll("execution").state)
            assertFalse(worker.evaluateRecovery("execution").getValue("noAuditStartProven").jsonPrimitive.boolean)
            assertThrows(JobRejected::class.java) { tryStart(worker) };assertEquals(1,startToolCalls.get())
        }
    }
    @Test fun nativeResponseBeforeCommitFailureRetainsHandleButIntentStaysUnknown() {
        val (worker,store,_)=startFixture("""{"status":"started","auditId":"native-fixture","auditRequestCount":4}""","__COMMIT__")
        store.use {
            assertThrows(java.io.IOException::class.java) { tryStart(worker) }
            assertEquals("SUBMISSION_UNKNOWN",worker.record("execution").state)
            assertEquals("native-fixture",worker.record("execution").auditId)
            assertNull(store.committedOnceResult("execution:start:0",fingerprint(worker.plan("execution").variants.single().variant)))
            assertEquals(JsonPrimitive("UNVERIFIED"),worker.startOutcome("execution").jsonObject["commitState"])
            assertEquals(JsonPrimitive(4),worker.lastKnownNativeMetrics("execution").getValue("auditRequestCount").jsonObject["value"])
            assertEquals("SUBMISSION_UNKNOWN",worker.poll("execution").state)
            assertThrows(JobRejected::class.java) { tryStart(worker) };assertEquals(1,startToolCalls.get())
        }
    }
    @Test fun identifiedUncommittedStartWithInterruptedMetadataCanUseFreshStopReviewWithoutResolvingIntent() {
        val (worker,store,_)=startFixture("""{"status":"started","auditId":"native-fixture"}""","__COMMIT__")
        store.use {
            assertThrows(java.io.IOException::class.java) { tryStart(worker) }
            store.put("execution:execution",jobJson.encodeToJsonElement(worker.record("execution").copy(state="SUBMITTING",auditId=null)))
            assertEquals("native-fixture",worker.record("execution").auditId)
            val evaluation=worker.evaluateRecovery("execution")
            assertFalse(evaluation.getValue("noAuditStartProven").jsonPrimitive.boolean)
            val recovered=worker.reconcileRecovery("execution",RecoverySelection(evaluation.getValue("currentSnapshotDigest").jsonPrimitive.content),"observed native terminal and shared stop","cleanup")
            assertEquals("MAINTENANCE_RESTORED_UNVERIFIED",recovered.state);assertEquals("INCOMPLETE",recovered.diagnosisState)
            assertNull(store.committedOnceResult("execution:start:0",fingerprint(worker.plan("execution").variants.single().variant)))
            assertEquals(1,startToolCalls.get());assertEquals(JsonNull,store.get("active"))
        }
    }
    @Test fun uncommittedRejectionDoesNotBecomeNoAuditRecoveryProof() {
        val (worker,store,_)=startFixture(LEGACY_SCAN_START_DENIED,"__COMMIT__")
        store.use {
            assertThrows(java.io.IOException::class.java) { tryStart(worker) }
            assertEquals("SUBMISSION_UNKNOWN",worker.record("execution").state)
            val evaluation=worker.evaluateRecovery("execution")
            assertFalse(evaluation.getValue("noAuditStartProven").jsonPrimitive.boolean)
            assertThrows(JobRejected::class.java) { worker.reconcileRecovery("execution",RecoverySelection(evaluation.getValue("currentSnapshotDigest").jsonPrimitive.content),"no committed proof","cleanup") }
            assertEquals(1,startToolCalls.get());assertEquals(JsonPrimitive("execution"),store.get("active"))
        }
    }


    @Test fun auditCommittedNoAuditSurvivesMissingFollowupMetadataWithoutInventingTimestamps() {
        val (worker,store,_)=startFixture(LEGACY_SCAN_START_DENIED)
        store.use {
            assertThrows(JobRejected::class.java) { tryStart(worker) }
            store.put("execution:execution",jobJson.encodeToJsonElement(worker.record("execution").copy(state="SUBMITTING")))
            store.put("start-outcome:execution:0",JsonNull);store.put("start-rejection:execution:0",JsonNull)
            val evaluation=worker.evaluateRecovery("execution")
            assertEquals(JsonPrimitive(true),evaluation["noAuditStartProven"])
            assertEquals(JsonNull,evaluation.getValue("startOutcome").jsonObject["observedAt"])
            val selection=RecoverySelection(evaluation.getValue("currentSnapshotDigest").jsonPrimitive.content)
            assertEquals("MAINTENANCE_RESTORED_UNVERIFIED",worker.reconcileRecovery("execution",selection,"independent shared stop evidence","metadata-cleanup").state)
            assertEquals(1,startToolCalls.get());assertEquals(JsonNull,store.get("active"))
        }
    }


    @Test fun auditCommittedNoAuditProofSupportsWorkerRestartWithoutBurpRestart() {
        val (worker,store,port)=startFixture(LEGACY_SCAN_START_DENIED)
        store.use {
            assertThrows(JobRejected::class.java) { tryStart(worker) }
            val reviewer=object:HumanApprover {
                override fun review(plan:CompiledPlan,stage:ApprovalStage,report:ValidationReport?)="human"
                override fun reviewReconciliation(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String,summary:JsonObject)="human"
            }
            val restarted=GuardedWorker(port,store,reviewer)
            val evaluation=restarted.evaluateRecovery("execution")
            val selection=RecoverySelection(evaluation.getValue("currentSnapshotDigest").jsonPrimitive.content)
            assertEquals("MAINTENANCE_RESTORED_UNVERIFIED",restarted.reconcileRecovery("execution",selection,"independent shared activity stop evidence","restart-cleanup").state)
            assertEquals(JsonNull,store.get("active"));assertEquals(1,startToolCalls.get())
        }
    }

    private val startToolCalls=AtomicInteger()
    private fun startFixture(reply:String,failKey:String?=null,failError:Throwable=java.io.IOException("anonymous metadata failure")):Triple<GuardedWorker,JobStore,Port> {
        val port=Port();port.current=port.current.copy(projectMarker="saved-project");port.commonRecoveryReady=true
        val api=io.mockk.mockk<burp.api.montoya.MontoyaApi>(relaxed=true)
        val cph=io.mockk.mockk<net.portswigger.mcp.execution.CphClient>(relaxed=true)
        val dispatch=ToolDispatch(true)
        dispatch.register("start_active_scan") { startToolCalls.incrementAndGet();listOf(io.modelcontextprotocol.kotlin.sdk.types.TextContent(reply)) }
        val adapter=net.portswigger.mcp.execution.MontoyaJobPort(api,dispatch,cph,"instance",emptySet(),directory,listOf(directory))
        val bridge=object:BurpExecutionPort by port {
            override fun start(variant:ScanVariant)=adapter.start(variant)
        }
        val reviewer=object:HumanApprover {
            override fun review(plan:CompiledPlan,stage:ApprovalStage,report:ValidationReport?)="human"
            override fun reviewReconciliation(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String,summary:JsonObject)="human"
        }
        val actualStore=JobStore(directory.resolve("fixture-store"))
        val store=if(failKey==null) actualStore else io.mockk.spyk(actualStore).also { failing ->
            if(failKey=="__COMMIT__") io.mockk.every { failing.onceJson("execution:start:0",any(),any()) } answers {
                val effect=thirdArg<()->JsonElement>()
                actualStore.onceJson(firstArg(),secondArg()) { effect();throw java.io.IOException("anonymous result commit failure") }
            } else io.mockk.every { failing.put(failKey,any<JsonElement>()) } answers {
                    if(startToolCalls.get()>0) throw failError else callOriginal()
                }
        }
        val worker=GuardedWorker(bridge,store,reviewer)
        worker.register("execution",proposal());worker.approve("execution",ApprovalStage.PREPARATION)
        worker.prepare("execution");worker.approve("execution",ApprovalStage.EXECUTION)
        return Triple(worker,store,port)
    }
    private fun tryStart(worker:GuardedWorker) {
        val approved=worker.record("execution");worker.start("execution",approved.fence,worker.epoch)
    }
    @Test fun auditExplicitPreAuditPermissionDenialMustNotBecomeSubmissionUnknown() {
        val (worker,store,port)=startFixture("Start active scan denied by Burp Suite")
        store.use {
            assertThrows(Exception::class.java) { tryStart(worker) }
            assertEquals(0,port.starts.get());assertNull(worker.record("execution").auditId)
            assertEquals("RECOVERY_REQUIRED",worker.record("execution").state)
        }
    }
    @Test fun auditKnownNoAuditDenialShouldPermitReviewedCleanupWithoutProcessRestart() {
        val (worker,store,port)=startFixture("Start active scan denied by Burp Suite")
        store.use {
            assertThrows(Exception::class.java) { tryStart(worker) }
            val evaluation=worker.evaluateRecovery("execution")
            val selection=RecoverySelection(evaluation.getValue("currentSnapshotDigest").jsonPrimitive.content)
            val result=assertDoesNotThrow<ExecutionRecord> { worker.reconcileRecovery("execution",selection,"independent stop evidence and no native audit created","cleanup") }
            assertEquals("MAINTENANCE_RESTORED_UNVERIFIED",result.state)
            assertEquals(JsonNull,store.get("active"));assertEquals(0,port.starts.get())
            val raw=store.get("start-rejection:execution:0")!!.jsonObject
            assertEquals(JsonPrimitive("SCAN_START_PERMISSION_DENIED"),raw["errorCode"])
            assertEquals(JsonPrimitive("PERMISSION_CHECK"),raw["stage"])
            assertEquals(JsonPrimitive("SCAN_START_PERMISSION_DENIED"),worker.evaluateRecovery("execution").getValue("startOutcome").jsonObject.getValue("result").jsonObject["errorCode"])
            val oldPlan=store.get("plan:execution");val oldValidation=store.get("validation:execution")
            val next=worker.recoveryProposal("execution",RecoveryReplanSelection(2))
            worker.register("next",next);worker.approve("next",ApprovalStage.PREPARATION);worker.prepare("next")
            worker.approve("next",ApprovalStage.EXECUTION)
            assertEquals("EXECUTION_APPROVED",worker.record("next").state)
            assertEquals(oldPlan,store.get("plan:execution"));assertEquals(oldValidation,store.get("validation:execution"))
            assertThrows(JobRejected::class.java) { tryStart(worker) };assertEquals(0,port.starts.get());assertEquals(1,startToolCalls.get())
        }
    }
    @Test fun auditUnclassifiedStartReplyMustRemainUnknownAndKeepOwner() {
        val (worker,store,_)=startFixture("unclassified transport reply")
        store.use {
            assertThrows(Exception::class.java) { tryStart(worker) }
            assertEquals("SUBMISSION_UNKNOWN",worker.record("execution").state)
            val evaluation=worker.evaluateRecovery("execution")
            val selection=RecoverySelection(evaluation.getValue("currentSnapshotDigest").jsonPrimitive.content)
            assertEquals("NATIVE_TERMINATION_UNPROVEN",assertThrows(JobRejected::class.java) { worker.reconcileRecovery("execution",selection,"insufficient stop evidence","cleanup") }.code)
            assertEquals(JsonPrimitive("execution"),store.get("active"))
        }
    }


    @Test fun publicCommonRecoveryResumesUnknownEffectAndCreatesFreshRevisionWithoutOldScanReplay() {
        val port=Port();port.current=port.current.copy(projectMarker="saved-project")
        port.readiness={false};port.commonRecoveryReady=true;port.failRecoveryAfterEffect=true
        val reviewer=object:HumanApprover {
            override fun review(plan:CompiledPlan,stage:ApprovalStage,report:ValidationReport?)="human"
            override fun reviewReconciliation(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String,summary:JsonObject)="human"
        }
        JobStore(directory.resolve("public-common-recovery")).use { store ->
            val worker=GuardedWorker(port,store,reviewer)
            val originalProposal=proposal().let { job ->
                val variant=job.variants.single()
                job.copy(variants=listOf(variant.copy(requiredBranches=listOf("normal","invalid_session"),
                    branchSetup=mapOf("invalid_session" to listOf(variant.request)))))
            }
            worker.register("execution",originalProposal);worker.approve("execution",ApprovalStage.PREPARATION)
            worker.prepare("execution");worker.approve("execution",ApprovalStage.EXECUTION)
            val approved=worker.record("execution");worker.start("execution",approved.fence,worker.epoch)
            store.put("execution:execution",jobJson.encodeToJsonElement(worker.record("execution").copy(state="SUBMISSION_UNKNOWN")))
            val oldPlan=store.get("plan:execution");val oldValidation=store.get("validation:execution")
            val sends=port.probes.get();val starts=port.starts.get()
            DiagnosticJobService(worker,store,false).use { service ->
                val evaluation=service.call(DiagnosticJob("recovery_evaluate","execution"))
                val selection=RecoverySelection(evaluation.getValue("currentSnapshotDigest").jsonPrimitive.content)
                service.call(DiagnosticJob("recovery_reconcile","execution",operationId="original-cleanup",evidenceRef="independent stop evidence",
                    recoverySelectionJson=jobJson.encodeToString(selection)))
                assertEquals(JsonPrimitive("FAILED"),await(service,"original-cleanup")["state"])
                assertEquals(JsonPrimitive("execution"),store.get("active"));assertEquals(1,port.reconciliations.get())
                service.call(DiagnosticJob("recovery_reconcile","execution",operationId="resume-cleanup",evidenceRef="independent stop evidence",
                    recoverySelectionJson=jobJson.encodeToString(selection.copy(resumeOperationId="original-cleanup"))))
                assertEquals(JsonPrimitive("SUCCEEDED"),await(service,"resume-cleanup")["state"])
                assertEquals(JsonNull,store.get("active"));assertEquals(1,port.reconciliations.get())
                assertEquals(sends,port.probes.get());assertEquals(starts,port.starts.get())
                val candidate=service.call(DiagnosticJob("recovery_replan","execution",operationId="fresh-revision",proposalJson=jobJson.encodeToString(RecoveryReplanSelection(2))))
                assertEquals(JsonPrimitive("STATIC_CHECKED"),candidate["state"])
                val legacy=service.drafts.validate("legacy-existing",worker.recoverySourceProposal("execution",RecoveryReplanSelection(2)),null)
                val legacyRead=service.call(DiagnosticJob("recovery_replan","execution",operationId="legacy-existing",
                    proposalJson=jobJson.encodeToString(RecoveryReplanSelection(2))))
                assertEquals(JsonPrimitive(legacy.draftDigest),legacyRead["draftDigest"])
                assertEquals(candidate,service.call(DiagnosticJob("recovery_replan","execution",operationId="fresh-revision",
                    proposalJson=jobJson.encodeToString(RecoveryReplanSelection(2)))))
                assertEquals("DRAFT_ID_REUSED",assertThrows(JobRejected::class.java) {
                    service.call(DiagnosticJob("recovery_replan","execution",operationId="fresh-revision",
                        proposalJson=jobJson.encodeToString(RecoveryReplanSelection(3))))
                }.code)
                service.call(DiagnosticJob("propose","retry",operationId="retry-proposal",draftId=candidate.getValue("draftId").jsonPrimitive.content,
                    draftDigest=candidate.getValue("draftDigest").jsonPrimitive.content))
                assertEquals(JsonPrimitive("SUCCEEDED"),await(service,"retry-proposal","retry")["state"])
                service.call(DiagnosticJob("prepare","retry",operationId="retry-preparation"))
                assertEquals(JsonPrimitive("SUCCEEDED"),await(service,"retry-preparation","retry")["state"])
                assertEquals(10,worker.validation("retry").probes.size)
                assertEquals(mapOf("normal" to 5,"invalid_session" to 5),worker.validation("retry").probes.groupingBy { it.branch }.eachCount())
                worker.approve("retry",ApprovalStage.EXECUTION)
                assertEquals("EXECUTION_APPROVED",worker.record("retry").state)
                assertEquals(starts,port.starts.get());assertEquals(oldPlan,store.get("plan:execution"));assertEquals(oldValidation,store.get("validation:execution"))
            }
        }
    }

    @Test fun `normal-only login preparation runs five complete probes without inventing bad-credential setup requests`() {
        val p=LoginPreparationFixture.proposal();val port=Port();port.current=LoginPreparationFixture.baseline
        port.probeOverride={ LoginPreparationFixture.login.response to JsonObject(emptyMap()) }
        JobStore(directory.resolve("normal-only-login")).use { store ->
            val worker=GuardedWorker(port,store,HumanApprover { _,_,_ -> "human" })
            DiagnosticJobService(worker,store,false).use { service ->
                service.call(DiagnosticJob("propose","execution",proposalJson=jobJson.encodeToString(p),operationId="normal-plan"))
                assertEquals(JsonPrimitive("SUCCEEDED"),await(service,"normal-plan")["state"])
                service.call(DiagnosticJob("prepare","execution",operationId="normal-preparation"))
                assertEquals(JsonPrimitive("SUCCEEDED"),await(service,"normal-preparation")["state"])
                val report=service.call(DiagnosticJob("validation","execution",count=100))
                assertEquals(5,report["totalProbes"]!!.jsonPrimitive.int)
                assertFalse(report.containsKey("preparationOnce"))
                assertFalse(report.containsKey("totalPreparationOnce"))
                assertEquals(List(5) { "normal" },report["probes"]!!.jsonArray.map { it.jsonObject["branch"]!!.jsonPrimitive.content })
                assertEquals(List(5) { "normal" to LoginPreparationFixture.login.request },port.observedProbeInputs)
                assertEquals(5,port.probes.get());assertEquals(0,port.starts.get());assertEquals(1,port.restores.get())
                assertEquals(comparableNativeCollections(LoginPreparationFixture.baseline.project),comparableNativeCollections(port.current.project))
                assertEquals(JsonNull,service.status("execution")["context"]!!.jsonObject["ownerExecutionId"])
            }
        }
    }
    @Test fun `one-time preparation evidence is paginated separately and never counted as repeated probes`() {
        val port=Port();val base=proposal();val v=base.variants.single()
        val plan=base.copy(variants=listOf(v.copy(preparationOnce=List(3) { v.request })))
        port.probeOverride={
            val id=port.probes.get()
            val entry=buildJsonObject {
                put("id",id);put("captureId","fixture-capture");put("tool","EXTENSIONS")
                put("request",request);put("response",response);put("responseState","RESPONSE_RECEIVED")
                putJsonObject("httpService") { put("host",endpoint.host);put("port",endpoint.port);put("secure",false) }
                put("requestTime","2026-01-01T00:00:00Z")
            }
            response to buildJsonObject {
                putJsonObject("before") { put("captureId","fixture-capture");put("latestId",id-1) }
                putJsonObject("after") { put("captureId","fixture-capture");put("latestId",id) }
                put("pages",JsonArray(listOf(JsonPrimitive(entry.toString()))))
            }
        }
        JobStore(directory.resolve("once-evidence-pagination")).use { store ->
            val worker=GuardedWorker(port,store,HumanApprover { _,_,_ -> "human" })
            DiagnosticJobService(worker,store,false).use { service ->
                service.call(DiagnosticJob("propose","execution",proposalJson=jobJson.encodeToString(plan),operationId="once-plan"))
                assertEquals(JsonPrimitive("SUCCEEDED"),await(service,"once-plan")["state"])
                service.call(DiagnosticJob("prepare","execution",operationId="once-prepare"))
                assertEquals(JsonPrimitive("SUCCEEDED"),await(service,"once-prepare")["state"])
                val first=service.call(DiagnosticJob("validation","execution",count=2))
                val second=service.call(DiagnosticJob("validation","execution",offset=2,count=2))
                assertEquals(5,first["totalProbes"]!!.jsonPrimitive.int)
                assertEquals(3,first["totalPreparationOnce"]!!.jsonPrimitive.int)
                assertEquals(listOf(0,1),first["preparationOnce"]!!.jsonArray.map { it.jsonObject["index"]!!.jsonPrimitive.int })
                assertEquals(listOf(2),second["preparationOnce"]!!.jsonArray.map { it.jsonObject["index"]!!.jsonPrimitive.int })
                assertEquals(2,first["probes"]!!.jsonArray.size)
                assertEquals(first["validationDigest"],second["validationDigest"])
                assertEquals(fingerprint(worker.validation("execution")),first["validationDigest"]!!.jsonPrimitive.content)
                assertEquals(3,port.once.get());assertEquals(5,port.probes.get());assertEquals(0,port.starts.get())
                service.call(DiagnosticJob("prepare","execution",operationId="once-prepare"))
                assertEquals(3,port.once.get())
                assertEquals(5,service.savedReviewFlows("execution").size)
            }
        }
    }
    @Test fun `MCP retirement is asynchronous human reviewed idempotent and leaves native and settings untouched`() {
        val port=Port();val entered=CountDownLatch(1);val release=CountDownLatch(1);val reviews=AtomicInteger()
        JobStore(directory.resolve("retirement")).use { store ->
            val old=GuardedWorker(port,store,HumanApprover { _,_,_ -> "human" })
            old.register("execution",proposal());old.approve("execution",ApprovalStage.PREPARATION);old.prepare("execution");old.approve("execution",ApprovalStage.EXECUTION)
            val r=old.record("execution");old.start("execution",r.fence,r.epoch);port.handlesMissing=true
            val preserved=port.current;val sends=port.probes.get();val restores=port.restores.get()
            lateinit var service:DiagnosticJobService
            val review=object:HumanApprover {
                override fun review(plan:CompiledPlan,stage:ApprovalStage,report:ValidationReport?)="human"
                override fun reviewRetirement(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String,currentDigest:String):String {
                    service.approvalPhase("AWAITING_RETIREMENT_APPROVAL");reviews.incrementAndGet();entered.countDown()
                    check(release.await(5,TimeUnit.SECONDS));service.approvalPhase("RUNNING");return "human"
                }
            }
            val replacement=GuardedWorker(port,store,review)
            DiagnosticJobService(replacement,store,false).use { live ->
                service=live
                val input=DiagnosticJob("retire","execution",operationId="retire-old",evidenceRef="operator current Project evidence")
                live.call(input);assertTrue(entered.await(3,TimeUnit.SECONDS))
                val waiting=live.status("execution")
                assertEquals(JsonPrimitive("execution"),waiting["context"]!!.jsonObject["ownerExecutionId"])
                assertEquals(JsonPrimitive("APPROVE_STAGE_IN_BURP_THEN_POLL_SAME_OPERATION"),waiting["nextAction"])
                release.countDown();assertEquals(JsonPrimitive("SUCCEEDED"),await(live,"retire-old")["state"])
                live.call(input);assertEquals(1,reviews.get())
                assertEquals("RETIRED_UNVERIFIED",replacement.record("execution").state)
                assertEquals(preserved,port.current);assertEquals(sends,port.probes.get());assertEquals(restores,port.restores.get());assertEquals(1,port.starts.get())
                assertEquals(JsonNull,live.status("execution")["context"]!!.jsonObject["ownerExecutionId"])
                assertFalse(live.status("execution")["diagnosisCompleted"]!!.jsonPrimitive.boolean)
            }
            DiagnosticJobService(replacement,store,true).use { unsupported ->
                assertEquals("HUMAN_MAINTENANCE_REVIEW_REQUIRED",assertThrows(JobRejected::class.java) {
                    unsupported.call(DiagnosticJob("retire","execution",operationId="no-auto",evidenceRef="proof"))
                }.code)
            }
        }
    }
    @Test fun `expired approval directs same audit renewal rather than only recovery`() {
        val port=Port()
        JobStore(directory.resolve("expired")).use { store ->
            val worker=GuardedWorker(port,store,HumanApprover { _,_,_ -> "human" })
            val originalProposal=proposal().let { job ->
                val variant=job.variants.single()
                job.copy(variants=listOf(variant.copy(requiredBranches=listOf("normal","invalid_session"),
                    branchSetup=mapOf("invalid_session" to listOf(variant.request)))))
            }
            worker.register("execution",originalProposal);worker.approve("execution",ApprovalStage.PREPARATION);worker.prepare("execution")
            worker.approve("execution",ApprovalStage.EXECUTION)
            val r=worker.record("execution");worker.start("execution",r.fence,r.epoch)
            val approval=jobJson.decodeFromJsonElement<ApprovalRecord>(store.get("approval:execution:EXECUTION")!!)
            store.put("approval:execution:EXECUTION",jobJson.encodeToJsonElement(approval.copy(expiresAt=approval.approvedAt)))
            assertEquals("CONTROL_REQUIRED",worker.poll("execution").state)
            DiagnosticJobService(worker,store,false).use { service ->
                assertEquals(JsonPrimitive("REVIEW_APPROVAL_THEN_RENEW_SAME_AUDIT_OR_RECOVER"),service.status("execution")["nextAction"])
                assertEquals(1,port.starts.get());assertEquals(10,port.probes.get())
            }
        }
    }
    @Test fun `stint binds the ordered selection and records final evidence without starting a scan`() {
        val port=Port()
        val decisions=mutableListOf<List<String>>()
        val reviewer=object:HumanApprover {
            override fun review(plan:CompiledPlan,stage:ApprovalStage,report:ValidationReport?)=error("unexpected individual review")
            override fun reviewStint(stintId:String,plans:List<CompiledPlan>,reports:List<ValidationReport>):String {
                decisions.add(plans.map { it.proposal.jobId })
                return "operator"
            }
        }
        JobStore(directory.resolve("stint")).use { store ->
            val worker=GuardedWorker(port,store,reviewer)
            val stints=PreparationStints(worker,store,java.util.concurrent.Executor { it.run() })
            val ids=listOf("first","second")
            ids.forEach { worker.register(it,proposal().copy(jobId=it)) }
            val create=DiagnosticStint("create","morning",ids)
            val manifest=stints.call(create)
            assertEquals(manifest,stints.call(create))
            val digest=manifest.getValue("manifestDigest").jsonPrimitive.content
            assertThrows(JobRejected::class.java) { stints.checkJobAction("first","prepare") }
            val prep=create.copy(action="review_preparation",manifestDigest=digest)
            assertThrows(JobRejected::class.java) { stints.call(prep.copy(executionIds=ids.reversed())) }
            stints.call(prep)
            assertThrows(JobRejected::class.java) { stints.checkJobAction("second","prepare") }
            ids.forEach { stints.checkJobAction(it,"prepare");worker.prepare(it) }
            val final=prep.copy(action="review_final")
            stints.call(final)
            stints.call(final)
            assertEquals(listOf(ids,ids),decisions)
            assertThrows(JobRejected::class.java) { stints.checkJobAction("first","execute") }
            assertEquals(10,port.probes.get());assertEquals(2,port.restores.get());assertEquals(0,port.starts.get())
            assertNull(store.get("approval:first:EXECUTION"))
        }
    }

    @Test fun `stint revisions keep history and hold after ten corrections`() {
        JobStore(directory.resolve("revision")).use { store ->
            val worker=GuardedWorker(Port(),store,HumanApprover { _,_,_ -> null })
            val stints=PreparationStints(worker,store,java.util.concurrent.Executor { it.run() })
            worker.register("r1",proposal())
            var manifest=stints.call(DiagnosticStint("create","s",listOf("r1"),1))
            for(revision in 2..12) {
                worker.register("r$revision",proposal().copy(revision=revision))
                val previous=manifest.getValue("manifestDigest").jsonPrimitive.content
                manifest=stints.call(DiagnosticStint("revise","s",listOf("r$revision"),manifestDigest=previous,
                    previousId="r${revision-1}",reason="updated settings"))
                assertNotNull(store.get("hw-manifest:$previous"))
            }
            val item=manifest.getValue("items").jsonArray.single().jsonObject
            assertEquals(JsonPrimitive("r11"),item["executionId"])
            assertEquals(JsonPrimitive("updated settings"),item["hold"])
        }
    }
    @TempDir lateinit var directory:Path
    private val caps=setOf("SCANNER_WORKFLOW","EXCLUSIVE_CONTEXT")
    private val endpoint=Endpoint("http","fixture.invalid",8080,"/item")
    private val request="GET /item HTTP/1.1\r\nHost: fixture.invalid:8080\r\n\r\n"
    private val response="HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    private fun proposal():JobProposal {
        val material=HttpMaterial("observed",endpoint,request,response,digest(request),digest(response))
        return JobProposal(jobId="service",revision=1,objective="Observed request workflow",targetPolicy=listOf(TargetPermit(endpoint)),
            materials=listOf(material),session=SessionPlan(false,"OMIT","Observed endpoint requires no authentication","fixture"),
            variants=listOf(ScanVariant("reflection","REFLECTION",request=RequestPlan(endpoint,request,material.id,material.requestSha256),settings=SettingsPlan())),
            requiredCapabilities=caps,cleanupPolicy="No created application data")
    }
    private inner class Port:BurpExecutionPort {
        var commonRecoveryReady=false
        var failRecoveryAfterEffect=false
        val reconciliations=AtomicInteger()
        override fun recoveryInventoryStopped()=commonRecoveryReady
        override fun recoveryTrafficObservation()=if(!commonRecoveryReady) JsonObject(emptyMap()) else buildJsonObject {
            put("activeTrackedMcpSends",0);put("captureHealth","NO_WINDOW_LOSS_OBSERVED");put("historicalMissingResponses",4)
            putJsonObject("cphActivity") { putJsonObject("active") { put("http_handler",0);put("helper_send",0) } }
        }
        override fun reconcileSettings(expected:BurpSnapshot,target:BurpSnapshot,operationId:String) {
            assertEquals(expected,current);reconciliations.incrementAndGet();current=target
            if(failRecoveryAfterEffect) throw IllegalStateException("effect finished, transport result unknown")
        }

        val observedProbeInputs=java.util.Collections.synchronizedList(mutableListOf<Pair<String,String>>())
        var probeOverride:(()->Pair<String,JsonObject>)?=null
        var readiness:()->Boolean={true}
        var handlesMissing=false
        override fun retirementReadiness(auditId:String)=handlesMissing
        var current=BurpSnapshot("fixture",buildJsonObject { putJsonObject("project_options") { putJsonObject("sessions") {} } },JsonObject(emptyMap()),emptyList(),caps)
        val starts=AtomicInteger();val probes=AtomicInteger();val restores=AtomicInteger();val once=AtomicInteger()
        override fun snapshot()=current
        override fun apply(variant:CompiledVariant) { current=current.copy(project=variant.project,cph=variant.cph,cphOrder=variant.cphOrder) }
        override fun restore(baseline:BurpSnapshot,ownedCphNames:Set<String>) { restores.incrementAndGet();current=baseline }
        override fun probe(variant:ScanVariant,branch:String):Pair<String,JsonObject> { probes.incrementAndGet();observedProbeInputs.add(branch to variant.request.request);return probeOverride?.invoke() ?: (response to JsonObject(emptyMap())) }
        override fun oncePreparation(request:RequestPlan):Pair<String,JsonObject> {
            val index=once.getAndIncrement()
            return response to buildJsonObject { put("onceOnlyIndex",index) }
        }
        override fun start(variant:ScanVariant):JsonObject { starts.incrementAndGet();return buildJsonObject { put("status","started");put("auditId","native-1") } }
        override fun poll(auditId:String):JsonObject {
            if(handlesMissing) throw JobRejected("AUDIT_NOT_TRACKED")
            return buildJsonObject { put("auditId",auditId);put("completed",true);put("auditStatusMessage","finished") }
        }
        override fun collect(auditId:String,payloadRunId:String?)=buildJsonObject { put("auditId",auditId);put("native",poll(auditId));put("complete",true);put("quiescent",true) }
        override fun recoveryReadiness(endpoints:List<Endpoint>)=readiness()
    }
    @Test fun `failed no-response prepare can recover after proven send return without replay or scan`() {
        val port=Port();val history=net.portswigger.mcp.tools.LoggerHttpHistory()
        val service=net.portswigger.mcp.schema.HttpService(endpoint.host,endpoint.port,false)
        port.readiness={history.quiescent(setOf(service))}
        port.probeOverride={
            val send=history.beginSend(service,request)
            history.recordRequest(1,"EXTENSIONS",service,"http://fixture.invalid:8080/item",request,null)
            assertFalse(port.readiness())
            history.endSend(send,service,request)
            throw JobRejected("HTTP_PROBE_DENIED_OR_NO_RESPONSE")
        }
        JobStore(directory.resolve("failed-get")).use { store ->
            val worker=GuardedWorker(port,store,HumanApprover { _,_,_ -> "human" })
            DiagnosticJobService(worker,store,false).use { live ->
                live.call(DiagnosticJob("propose","execution",proposalJson=jobJson.encodeToString(proposal()),operationId="proposal"))
                assertEquals(JsonPrimitive("SUCCEEDED"),await(live,"proposal")["state"])
                val prepare=DiagnosticJob("prepare","execution",operationId="prepare-once")
                live.call(prepare)
                assertEquals(JsonPrimitive("HTTP_PROBE_DENIED_OR_NO_RESPONSE"),await(live,"prepare-once")["errorCode"])
                assertEquals("RECOVERY_REQUIRED",worker.record("execution").state)
                assertEquals(1,port.probes.get());assertEquals(0,port.starts.get())
                live.call(prepare);live.status("execution");assertEquals(1,port.probes.get())
                live.call(DiagnosticJob("recover","execution",operationId="recover-once",evidenceRef="native send returned without response; no audit started"))
                assertEquals(JsonPrimitive("SUCCEEDED"),await(live,"recover-once")["state"])
                assertEquals("FAILED_RECONCILED",worker.record("execution").state)
                assertEquals(JsonNull,live.status("execution")["context"]!!.jsonObject["ownerExecutionId"])
                assertEquals(1,port.probes.get());assertEquals(0,port.starts.get())
                assertFalse(live.status("execution")["diagnosisCompleted"]!!.jsonPrimitive.boolean)
                val evidence=history.snapshot().single()
                assertEquals("NO_RESPONSE_OBSERVED",evidence.responseState);assertNull(evidence.response)
                assertEquals("SEND_RETURNED",evidence.sendCompletionState)
            }
        }
    }
    private fun await(service:DiagnosticJobService,id:String,executionId:String="execution"):JsonObject {
        val limit=System.nanoTime()+TimeUnit.SECONDS.toNanos(10)
        while(System.nanoTime()<limit) {
            val op=service.call(DiagnosticJob("operation",executionId,operationId=id))
            if(op["state"]!=JsonPrimitive("RUNNING")) return op
            Thread.sleep(10)
        }
        error("Specific operation $id did not finish")
    }
    @Test fun `approval does not block MCP status and approved job completes without another client process`() {
        val entered=CountDownLatch(1);val release=CountDownLatch(1);val port=Port()
        JobStore(directory.resolve("store")).use { store ->
            lateinit var runningService:DiagnosticJobService
            val approver=HumanApprover { _,stage,_ ->
                if(stage==ApprovalStage.PREPARATION) {
                    runningService.approvalPhase("AWAITING_PREPARATION_APPROVAL")
                    entered.countDown();check(release.await(5,TimeUnit.SECONDS));runningService.approvalPhase("RUNNING")
                };"human"
            }
            val worker=GuardedWorker(port,store,approver)
            DiagnosticJobService(worker,store,false).use { service ->
                runningService=service
                service.call(DiagnosticJob("propose","execution",proposalJson=jobJson.encodeToString(proposal()),operationId="proposal"))
                assertEquals(JsonPrimitive("SUCCEEDED"),await(service,"proposal")["state"])
                val first=service.call(DiagnosticJob("prepare","execution",operationId="preparation"))
                assertTrue(entered.await(3,TimeUnit.SECONDS));assertEquals(JsonPrimitive("RUNNING"),first["state"])
                assertEquals(JsonPrimitive("APPROVE_STAGE_IN_BURP_THEN_POLL_SAME_OPERATION"),service.status("execution")["nextAction"])
                val duplicate=service.call(DiagnosticJob("prepare","execution",operationId="new-id-while-waiting"))
                assertEquals(first["operationId"],duplicate["operationId"]);assertEquals(0,port.starts.get())
                release.countDown()
                val prepared=await(service,"preparation");assertEquals(JsonPrimitive("SUCCEEDED"),prepared["state"])
                assertEquals(5,port.probes.get());assertEquals(1,port.restores.get())
                val digest=prepared["result"]!!.jsonObject["validationDigest"]!!.jsonPrimitive.content
                val execute=DiagnosticJob("execute","execution",operationId="execution-run",validationDigest=digest)
                service.call(DiagnosticJob("plan_next","execution",nextTargetsJson="[]"))
                service.call(execute)
                assertEquals(JsonPrimitive("SUCCEEDED"),await(service,"execution-run")["state"])
                assertEquals("EXECUTION_FINISHED",worker.record("execution").state)
                assertEquals(1,port.starts.get());assertEquals(6,port.probes.get());assertEquals(2,port.restores.get())
                service.call(execute);assertEquals(1,port.starts.get())
                assertFalse(service.call(DiagnosticJob("results","execution"))["diagnosisCompleted"]!!.jsonPrimitive.boolean)
            }
        }
    }
    @Test fun `operation identifiers are bound to the exact request and interrupted intents never replay`() {
        val port=Port()
        JobStore(directory.resolve("store")).use { store ->
            val worker=GuardedWorker(port,store,HumanApprover { _,_,_ -> "human" })
            store.put("mcp-operation:interrupted",buildJsonObject {
                put("operationId","interrupted");put("executionId","execution");put("action","execute");put("state","RUNNING");put("requestDigest","old")
            })
            DiagnosticJobService(worker,store,true).use { service ->
                val status=service.call(DiagnosticJob("operation","execution",operationId="interrupted"))
                assertEquals(JsonPrimitive("OUTCOME_UNKNOWN"),status["state"]);assertEquals(0,port.starts.get())
                assertThrows(JobRejected::class.java) { service.call(DiagnosticJob("execute","execution",operationId="interrupted",validationDigest="changed")) }
            }
        }
    }
    @Test fun `Quick runs the same validated workflow through completion without any dialog delegate`() {
        val port=Port()
        JobStore(directory.resolve("store")).use { store ->
            val noDialog=ConfiguredJobApprover(HumanApprover { _,_,_ -> error("Quick must not show an approval") },true)
            val worker=GuardedWorker(port,store,noDialog)
            DiagnosticJobService(worker,store,true).use { service ->
                service.call(DiagnosticJob("propose","execution",proposalJson=jobJson.encodeToString(proposal()),operationId="quick-proposal"));await(service,"quick-proposal")
                service.call(DiagnosticJob("prepare","execution",operationId="quick-prepare"))
                val prepared=await(service,"quick-prepare");assertEquals(JsonPrimitive("SUCCEEDED"),prepared["state"])
                val digest=prepared["result"]!!.jsonObject["validationDigest"]!!.jsonPrimitive.content
                service.call(DiagnosticJob("plan_next","execution",nextTargetsJson="[]"))
                service.call(DiagnosticJob("execute","execution",operationId="quick-execute",validationDigest=digest))
                assertEquals(JsonPrimitive("SUCCEEDED"),await(service,"quick-execute")["state"])
                assertEquals("EXECUTION_FINISHED",worker.record("execution").state)
                assertEquals(1,port.starts.get());assertEquals(6,port.probes.get())
                assertEquals(JsonPrimitive("QUICK"),service.status("execution")["mode"])
            }
        }
    }
    @Test fun `denied stage reports explicit retry consistently without starting communication`() {
        val port=Port();val decisions=AtomicInteger()
        JobStore(directory.resolve("store")).use { store ->
            val worker=GuardedWorker(port,store,HumanApprover { _,_,_ -> decisions.incrementAndGet();null })
            DiagnosticJobService(worker,store,false).use { service ->
                service.call(DiagnosticJob("propose","execution",proposalJson=jobJson.encodeToString(proposal()),operationId="denied-proposal"))
                await(service,"denied-proposal")
                val prepare=DiagnosticJob("prepare","execution",operationId="denied-prepare")
                service.call(prepare)
                val denied=await(service,"denied-prepare")
                assertEquals(JsonPrimitive("HUMAN_DENIED"),denied["errorCode"])
                assertEquals(JsonPrimitive("WAIT_FOR_EXPLICIT_USER_RETRY"),denied["nextAction"])
                assertEquals(denied["nextAction"],service.status("execution")["nextAction"])
                service.call(prepare)
                assertEquals(1,decisions.get());assertEquals(0,port.probes.get());assertEquals(0,port.starts.get())
            }
        }
    }
}
