package net.portswigger.mcp.jobs

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import net.portswigger.diagnosis.runner.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class JobDraftPlanningTest {
    @TempDir lateinit var directory:Path
    private fun worker(port:DraftTestFixture.Port,store:JobStore)=GuardedWorker(port,store,HumanApprover { _,_,_ -> "mock-human" })

    @Test fun `draft validation uses stored pre-apply baseline during a running scan without any port calls or fences`() {
        val port=DraftTestFixture.Port()
        JobStore(directory.resolve("running")).use { store ->
            val worker=worker(port,store);DraftTestFixture.start(worker)
            val calls=port.calls();val fence=store.get("fence");val active=store.get("active");val current=port.current
            val drafts=JobDrafts(worker,store)
            val record=drafts.validate("draft-one",DraftTestFixture.proposal(),"current")
            assertEquals(DraftTestFixture.baseline,record.plan.baseline)
            assertEquals(calls,port.calls());assertEquals(current,port.current)
            assertEquals(fence,store.get("fence"));assertEquals(active,store.get("active"))
            assertTrue(store.keys("approval:next").isEmpty());assertNull(store.get("execution:next"))
            val report=drafts.report(record)
            assertEquals(JsonPrimitive("STATIC_CHECKED"),report["state"]);assertEquals(JsonPrimitive(false),report["executable"])
            assertEquals("RUNNING",worker.record("current").state)
            assertEquals("DRAFT_BASELINE_EXECUTION_REQUIRED",assertThrows(JobRejected::class.java) {
                drafts.validate("without-source",DraftTestFixture.proposal(),null)
            }.code)
            assertEquals(calls,port.calls());assertNull(store.get("draft:without-source"))
        }
    }
    @Test fun `static checks do not wait for a worker monitor held by a blocked macro`() {
        val port=DraftTestFixture.Port();val entered=CountDownLatch(1);val release=CountDownLatch(1)
        val threads=Executors.newFixedThreadPool(2)
        JobStore(directory.resolve("blocking")).use { store ->
            val worker=worker(port,store);worker.register("current",DraftTestFixture.proposal("current"))
            worker.approve("current",ApprovalStage.PREPARATION);port.gate=entered to release
            val preparation=threads.submit<ValidationReport> { worker.prepare("current") }
            try {
                assertTrue(entered.await(3,TimeUnit.SECONDS))
                val calls=port.calls()
                val draft=threads.submit<JobDraft> { JobDrafts(worker,store).validate("overlap",DraftTestFixture.proposal(),"current") }
                    .get(2,TimeUnit.SECONDS)
                assertEquals(DraftTestFixture.baseline,draft.plan.baseline);assertEquals(calls,port.calls())
                assertFalse(preparation.isDone);assertEquals(JsonPrimitive("current"),store.get("active"))
            } finally { release.countDown();port.gate=null;preparation.get(5,TimeUnit.SECONDS);threads.shutdownNow() }
            assertEquals(5,port.probes.get());assertEquals(0,port.starts.get());assertEquals(1,port.restores.get())
        }
    }
    @Test fun `idle drafts are immutable idempotent persisted and do not freeze inputs or become executions`() {
        val port=DraftTestFixture.Port();lateinit var saved:JobDraft
        val proposal=DraftTestFixture.proposal()
        JobStore(directory.resolve("persisted")).use { store ->
            val drafts=JobDrafts(worker(port,store),store)
            saved=drafts.validate("persisted",proposal,null)
            assertEquals(1,port.snapshots.get());val calls=port.calls()
            assertEquals(saved,drafts.validate("persisted",proposal,null));assertEquals(calls,port.calls())
            assertEquals("DRAFT_ID_REUSED",assertThrows(JobRejected::class.java) {
                drafts.validate("persisted",proposal.copy(revision=2),null)
            }.code)
            assertNull(store.get("fence"));assertNull(store.get("execution:persisted"));assertEquals(0,port.freezes.get())
        }
        JobStore(directory.resolve("persisted")).use { store ->
            val drafts=JobDrafts(worker(port,store),store)
            assertEquals(saved,drafts.load("persisted",saved.draftDigest))
            assertEquals("DRAFT_DIGEST_MISMATCH",assertThrows(JobRejected::class.java) { drafts.load("persisted","wrong") }.code)
            assertEquals("DRAFT_NOT_FOUND",assertThrows(JobRejected::class.java) { drafts.load("absent") }.code)
        }
    }
    @Test fun `failed static compilation does not persist a passing draft or formal execution`() {
        val port=DraftTestFixture.Port()
        JobStore(directory.resolve("invalid")).use { store ->
            val worker=worker(port,store);worker.register("source",DraftTestFixture.proposal("source"))
            val drafts=JobDrafts(worker,store);val calls=port.calls();val p=DraftTestFixture.proposal()
            val bad=p.copy(materials=p.materials.map { it.copy(requestSha256="changed") })
            assertEquals("MATERIAL_CHANGED",assertThrows(JobRejected::class.java) { drafts.validate("bad",bad,"source") }.code)
            assertNull(store.get("draft:bad"));assertNull(store.get("execution:bad"));assertEquals(calls,port.calls())
            assertEquals("NOT_FOUND",assertThrows(JobRejected::class.java) { drafts.validate("no-source",p,"absent") }.code)
        }
    }
    @Test fun `payload draft validates hashes as declarations without opening or freezing the referenced files`() {
        val port=DraftTestFixture.Port()
        JobStore(directory.resolve("offline-files")).use { store ->
            val worker=worker(port,store);DraftTestFixture.start(worker)
            val p=DraftTestFixture.proposal();val v=p.variants.single()
            val missing=directory.resolve("not-created-workbook.xlsx").toString()
            val options=buildJsonObject { putJsonObject("payloadProfile") { put("tier","medium");put("workbookPath",missing) } }
            val proposal=p.copy(inputDigests=mapOf(missing to "0".repeat(64)),
                variants=listOf(v.copy(request=v.request.copy(startOptions=options))))
            val before=port.calls()
            val draft=JobDrafts(worker,store).validate("offline-files",proposal,"current")
            assertEquals(proposal.inputDigests,draft.plan.proposal.inputDigests)
            assertEquals(before,port.calls());assertFalse(java.nio.file.Files.exists(Path.of(missing)))
        }
    }
    @Test fun `draft compilation preserves native login macro CPH response definitions and original scan selectors`() {
        val port=DraftTestFixture.Port();port.current=LoginPreparationFixture.baseline
        JobStore(directory.resolve("dynamic")).use { store ->
            val drafts=JobDrafts(worker(port,store),store);val p=LoginPreparationFixture.proposal()
            val d=drafts.validate("login-plan",p,null)
            assertEquals(p,d.plan.proposal)
            assertEquals(p.variants.single().settings.cph,d.plan.variants.single().cph)
            assertEquals(p.variants.single().request.startOptions,d.plan.variants.single().variant.request.startOptions)
            assertEquals(0,port.freezes.get());assertEquals(0,port.probes.get());assertEquals(0,port.starts.get())
        }
    }
    @Test fun `promotion after completion recompiles against fresh unrelated settings and still requires five checks and approval`() {
        val port=DraftTestFixture.Port()
        JobStore(directory.resolve("promote")).use { store ->
            val worker=worker(port,store);DraftTestFixture.start(worker)
            val draft=JobDrafts(worker,store).validate("future",DraftTestFixture.proposal(),"current")
            val before=port.calls()
            assertEquals("BURP_CONTEXT_BUSY",assertThrows(JobRejected::class.java) { worker.registerDraft("next",draft) }.code)
            assertEquals(before,port.calls());assertNull(store.get("execution:next"))
            port.completed=true;worker.poll("current")
            port.current=port.current.copy(project=JsonObject(port.current.project+("unrelated" to JsonPrimitive("keep"))))
            val fresh=port.current
            val plan=worker.registerDraft("next",draft)
            assertEquals(fresh,plan.baseline);assertNotEquals(draft.plan.planDigest,plan.planDigest)
            assertEquals(JsonPrimitive(true),store.get("draft-origin:next")!!.jsonObject["baselineChangedSinceDraft"])
            assertNull(store.get("approval:next:PREPARATION"));assertNull(store.get("validation:next"))
            assertEquals("INVALID_STATE",assertThrows(JobRejected::class.java) { worker.prepare("next") }.code)
            val probes=port.probes.get();worker.approve("next",ApprovalStage.PREPARATION);worker.prepare("next")
            assertEquals(probes+5,port.probes.get());assertEquals(fresh,port.current)
            assertEquals(1,port.starts.get());assertEquals("VALIDATED",worker.record("next").state)
        }
    }
    @Test fun `changed original input or secret generation refuses promotion before freezing or approval`() {
        for(secret in listOf(false,true)) {
            val port=DraftTestFixture.Port()
            JobStore(directory.resolve("inputs-$secret")).use { store ->
                val worker=worker(port,store);val draft=JobDrafts(worker,store).validate("frozen-later",DraftTestFixture.proposal(),null)
                port.inputChanged=!secret;port.secretChanged=secret
                assertEquals(if(secret) "SECRET_GENERATION_CHANGED_OR_UNAVAILABLE" else "APPROVED_INPUT_CHANGED",
                    assertThrows(JobRejected::class.java) { worker.registerDraft("next",draft) }.code)
                assertEquals(0,port.freezes.get());assertEquals(0,port.starts.get());assertNull(store.get("execution:next"))
            }
        }
    }
    @Test fun `fresh capability loss refuses a formerly passing draft without inheriting its baseline`() {
        val port=DraftTestFixture.Port()
        JobStore(directory.resolve("capability")).use { store ->
            val worker=worker(port,store);val draft=JobDrafts(worker,store).validate("capabilities",DraftTestFixture.proposal(),null)
            port.current=port.current.copy(capabilities=emptySet())
            assertEquals("UNSUPPORTED_CAPABILITY",assertThrows(JobRejected::class.java) { worker.registerDraft("next",draft) }.code)
            assertNull(store.get("execution:next"));assertTrue(port.current.capabilities.isEmpty())
        }
    }
    @Test fun `fresh macro collision refuses promotion rather than overwriting current definitions`() {
        val port=DraftTestFixture.Port();port.current=LoginPreparationFixture.baseline
        JobStore(directory.resolve("collision")).use { store ->
            val worker=worker(port,store);val p=LoginPreparationFixture.proposal()
            val draft=JobDrafts(worker,store).validate("native-ids",p,null)
            val project=port.current.project
            val root=project["project_options"]!!.jsonObject
            val sessions=root["sessions"]!!.jsonObject
            val macros=sessions["macros"] as? JsonObject ?: JsonObject(emptyMap())
            val withCollision=JsonObject(macros+("macros" to JsonArray(listOf(p.variants.single().settings.macros.first()))))
            val modified=JsonObject(sessions+("macros" to withCollision))
            port.current=port.current.copy(project=JsonObject(project+("project_options" to JsonObject(root+("sessions" to modified)))))
            val fresh=port.current
            assertEquals("MACRO_ID_COLLISION",assertThrows(JobRejected::class.java) { worker.registerDraft("next",draft) }.code)
            assertEquals(fresh,port.current);assertNull(store.get("execution:next"));assertNull(store.get("draft-origin:next"))
        }
    }
}
