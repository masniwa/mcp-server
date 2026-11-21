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

class LookAheadPlannerTest {
    @TempDir lateinit var directory: Path
    private fun worker(port: DraftTestFixture.Port, store: JobStore) =
        GuardedWorker(port, store, HumanApprover { _, _, _ -> "mock-human" })
    private fun declaration(proposal: JobProposal, taskId: String = "next-task"): JsonObject {
        val reflection = proposal.variants.single { it.kind == "REFLECTION" }
        val material = proposal.materials.single { it.id == reflection.request.sourceId }
        return buildJsonObject {
            put("taskId", taskId); put("jobId", proposal.jobId)
            put("endpoint", jobJson.encodeToJsonElement(material.endpoint))
            put("sourceId", material.id); put("sourceRequestSha256", material.requestSha256)
        }
    }
    private fun declare(planner: LookAheadPlanner, proposal: JobProposal, taskId: String = "next-task") =
        planner.declare("current", JsonArray(listOf(declaration(proposal, taskId))).toString())
    private fun task(report: JsonObject, id: String = "next-task"): JsonObject =
        report.getValue("states").jsonArray.map { it.jsonObject }.single { it["taskId"] == JsonPrimitive(id) }
    private fun await(planner: LookAheadPlanner, state: String, id: String = "next-task"): JsonObject {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(4)
        while (System.nanoTime() < deadline) {
            val found = task(planner.report("current"), id)
            if (found["state"] == JsonPrimitive(state)) return found
            Thread.sleep(10)
        }
        fail<JsonObject>("Specific look-ahead task did not reach $state: ${planner.report("current")}")
        error("unreachable")
    }
    private fun prepared(worker: GuardedWorker) {
        worker.register("current", DraftTestFixture.proposal("current"))
        worker.approve("current", ApprovalStage.PREPARATION); worker.prepare("current")
    }
    private fun start(worker: GuardedWorker) {
        worker.approve("current", ApprovalStage.EXECUTION)
        val current = worker.record("current"); worker.start("current", current.fence, current.epoch)
    }

    @Test fun `running Scan automatically statically checks a supplied next proposal once without port calls or formal state changes`() {
        val port = DraftTestFixture.Port()
        JobStore(directory.resolve("automatic")).use { store ->
            val worker = worker(port, store); DraftTestFixture.start(worker)
            val drafts = JobDrafts(worker, store)
            LookAheadPlanner(worker, store, drafts).use { planner ->
                val proposal = DraftTestFixture.proposal().copy(objective = "secret-not-for-report")
                val before = port.calls(); val fence = store.get("fence"); val active = store.get("active"); val record = worker.record("current")
                val missing = declare(planner, proposal)
                assertEquals(JsonPrimitive("CONFIGURATION_REQUIRED"), task(missing)["state"])
                planner.submit("current", "next-task", "next-draft", proposal)
                val checked = await(planner, "STATIC_CHECKED")
                assertEquals(JsonPrimitive(true), checked["checkedDuringScan"])
                assertEquals(JsonPrimitive(false), checked["windowMissed"])
                val saved = drafts.load("next-draft")
                assertEquals("current", saved.baselineExecutionId)
                assertEquals(JsonPrimitive(saved.draftDigest), checked["draftDigest"])
                repeat(3) { planner.onRunning("current"); planner.submit("current", "next-task", "next-draft", proposal) }
                assertEquals(listOf("draft:next-draft"), store.keys("draft:"))
                assertEquals(before, port.calls()); assertEquals(fence, store.get("fence")); assertEquals(active, store.get("active"))
                assertEquals(record, worker.record("current")); assertNull(store.get("execution:next")); assertTrue(store.keys("approval:next").isEmpty())
                val report = planner.report("current")
                assertFalse(report.toString().contains("secret-not-for-report"))
                assertEquals(JsonPrimitive(false), report["automaticConfigurationGeneration"])
                assertEquals(JsonPrimitive(true), report["automaticStaticValidation"])
            }
        }
    }

    @Test fun `declaration is explicit immutable idempotent and an empty queue means the last target`() {
        val port = DraftTestFixture.Port()
        JobStore(directory.resolve("declarations")).use { store ->
            val worker = worker(port, store); worker.register("current", DraftTestFixture.proposal("current"))
            LookAheadPlanner(worker, store, JobDrafts(worker, store)).use { planner ->
                assertEquals("LOOKAHEAD_TARGETS_DECLARATION_REQUIRED", assertThrows(JobRejected::class.java) { planner.requireDeclared("current") }.code)
                val before = port.calls()
                val last = planner.declare("current", "[]"); planner.requireDeclared("current")
                assertEquals(JsonPrimitive(true), last["lastTarget"])
                assertEquals(JsonPrimitive("NO_NEXT_TARGET"), last["agentNextAction"])
                assertEquals(last, planner.declare("current", "[ ]"))
                assertEquals("LOOKAHEAD_DECLARATION_CHANGED", assertThrows(JobRejected::class.java) { declare(planner, DraftTestFixture.proposal()) }.code)
                assertEquals(before, port.calls())
                val absent = planner.report("not-yet-registered")
                assertEquals(JsonPrimitive(false), absent["declared"]); assertEquals(JsonNull, absent["parentState"])
                assertEquals(JsonPrimitive("NO_REGISTERED_NEXT_TARGET_WORK"), absent["agentNextAction"])
            }
        }
    }

    @Test fun `target binding refuses another job source hash or material endpoint before storing a proposal`() {
        val port = DraftTestFixture.Port()
        JobStore(directory.resolve("binding")).use { store ->
            val worker = worker(port, store); worker.register("current", DraftTestFixture.proposal("current"))
            LookAheadPlanner(worker, store, JobDrafts(worker, store)).use { planner ->
                val p = DraftTestFixture.proposal(); declare(planner, p); val before = port.calls()
                val v = p.variants.single()
                val bad = listOf(p.copy(jobId = "different"),
                    p.copy(variants = listOf(v.copy(request = v.request.copy(sourceId = "wrong-source")))),
                    p.copy(variants = listOf(v.copy(request = v.request.copy(sourceRequestSha256 = "0".repeat(64))))),
                    p.copy(materials = p.materials.map { it.copy(endpoint = it.endpoint.copy(path = "/other")) }))
                bad.forEachIndexed { index, proposal ->
                    assertEquals("LOOKAHEAD_TARGET_MISMATCH", assertThrows(JobRejected::class.java) {
                        planner.submit("current", "next-task", "bad-$index", proposal)
                    }.code)
                }
                assertEquals(JsonPrimitive("CONFIGURATION_REQUIRED"), task(planner.report("current"))["state"])
                assertTrue(store.keys("draft:").isEmpty()); assertEquals(before, port.calls())
            }
        }
    }

    @Test fun `ready later tasks are checked while earlier missing information remains visible and order is retained`() {
        val port = DraftTestFixture.Port()
        JobStore(directory.resolve("independent")).use { store ->
            val worker = worker(port, store); DraftTestFixture.start(worker)
            LookAheadPlanner(worker, store, JobDrafts(worker, store)).use { planner ->
                val first = DraftTestFixture.proposal("next-one"); val second = DraftTestFixture.proposal("next-two")
                planner.declare("current", JsonArray(listOf(declaration(first, "one"), declaration(second, "two"))).toString())
                planner.information("current", "one", listOf("Current attributes and an observed partial restore are missing"))
                val before = port.calls(); planner.submit("current", "two", "second-draft", second)
                await(planner, "STATIC_CHECKED", "two")
                val report = planner.report("current")
                assertEquals(JsonPrimitive("one"), report["nextTaskId"])
                assertEquals(JsonPrimitive("INFORMATION_REQUIRED"), task(report, "one")["state"])
                assertEquals(listOf("one", "two"), report["states"]!!.jsonArray.map { it.jsonObject["taskId"]!!.jsonPrimitive.content })
                planner.submit("current", "one", "first-draft", first); await(planner, "STATIC_CHECKED", "one")
                assertEquals(before, port.calls())
            }
        }
    }

    @Test fun `static failure does not change current Scan and a correction requires new revision and immutable draft ID`() {
        val port = DraftTestFixture.Port()
        JobStore(directory.resolve("failure")).use { store ->
            val worker = worker(port, store); DraftTestFixture.start(worker)
            LookAheadPlanner(worker, store, JobDrafts(worker, store)).use { planner ->
                val good = DraftTestFixture.proposal(); declare(planner, good)
                val bad = good.copy(materials = good.materials.map { it.copy(responseSha256 = "0".repeat(64)) })
                val before = port.calls(); val record = worker.record("current")
                planner.submit("current", "next-task", "bad-draft", bad)
                val failed = await(planner, "STATIC_FAILED")
                assertEquals(JsonPrimitive("MATERIAL_CHANGED"), failed["errorCode"])
                planner.submit("current", "next-task", "bad-draft", bad)
                assertNull(store.get("draft:bad-draft"))
                assertEquals("LOOKAHEAD_NEW_REVISION_REQUIRED", assertThrows(JobRejected::class.java) { planner.submit("current", "next-task", "corrected", good) }.code)
                assertEquals("LOOKAHEAD_DRAFT_ID_REUSED", assertThrows(JobRejected::class.java) { planner.submit("current", "next-task", "bad-draft", good.copy(revision = 2)) }.code)
                planner.submit("current", "next-task", "corrected", good.copy(revision = 2))
                val checked = await(planner, "STATIC_CHECKED")
                assertEquals(1, checked["priorAttempts"]!!.jsonArray.size)
                assertEquals(before, port.calls()); assertEquals(record, worker.record("current"))
            }
        }
    }

    @Test fun `queued work waits before a Scan starts and compiles after onRunning without a second submission`() {
        val port = DraftTestFixture.Port()
        JobStore(directory.resolve("queued")).use { store ->
            val worker = worker(port, store); prepared(worker)
            LookAheadPlanner(worker, store, JobDrafts(worker, store)).use { planner ->
                val p = DraftTestFixture.proposal(); declare(planner, p)
                assertEquals(JsonPrimitive("QUEUED"), task(planner.submit("current", "next-task", "queued", p))["state"])
                assertNull(store.get("draft:queued"))
                start(worker); val before = port.calls(); planner.onRunning("current")
                await(planner, "STATIC_CHECKED"); assertEquals(before, port.calls())
            }
        }
    }

    @Test fun `missed window does not compile but explicit submission may bind an actual separately checked result`() {
        val port = DraftTestFixture.Port()
        JobStore(directory.resolve("missed")).use { store ->
            val worker = worker(port, store); prepared(worker)
            val drafts = JobDrafts(worker, store)
            LookAheadPlanner(worker, store, drafts).use { planner ->
                val p = DraftTestFixture.proposal(); declare(planner, p); planner.submit("current", "next-task", "late", p)
                start(worker); port.completed = true; worker.poll("current")
                val before = port.calls(); planner.onRunning("current")
                assertEquals(JsonPrimitive("WINDOW_MISSED"), task(planner.report("current"))["state"])
                assertNull(store.get("draft:late")); assertEquals(before, port.calls())
                val manuallyChecked = drafts.validate("late", p, "current")
                val late = task(planner.submit("current", "next-task", "late", p))
                assertEquals(JsonPrimitive("STATIC_CHECKED"), late["state"])
                assertEquals(JsonPrimitive(false), late["checkedDuringScan"]); assertEquals(JsonPrimitive(true), late["windowMissed"])
                planner.requirePromotion(p, "late", manuallyChecked.draftDigest); assertEquals(before, port.calls())
            }
        }
    }

    @Test fun `a new worker does not replay stale queued proposals but may bind an explicitly validated immutable draft`() {
        val port = DraftTestFixture.Port()
        JobStore(directory.resolve("stale")).use { store ->
            val first = worker(port, store); prepared(first); val p = DraftTestFixture.proposal()
            LookAheadPlanner(first, store, JobDrafts(first, store)).use { planner ->
                declare(planner, p); planner.submit("current", "next-task", "old-queued", p)
            }
            val second = worker(port, store); val drafts = JobDrafts(second, store)
            LookAheadPlanner(second, store, drafts).use { planner ->
                val before = port.calls(); planner.onRunning("current")
                assertEquals(JsonPrimitive("STALE_WORKER_EPOCH"), task(planner.report("current"))["state"])
                assertNull(store.get("draft:old-queued"))
                planner.requirePromotion(p, null, null) // An old Project/worker queue cannot gate a new context.
                assertEquals("LOOKAHEAD_PARENT_EPOCH_CHANGED", assertThrows(JobRejected::class.java) {
                    planner.submit("current", "next-task", "new-id", p.copy(revision = 2))
                }.code)
                val corrected = p.copy(revision = 2); val checked = drafts.validate("explicit", corrected, "current")
                val report = planner.submit("current", "next-task", "explicit", corrected)
                assertEquals(JsonPrimitive("STATIC_CHECKED"), task(report)["state"])
                assertEquals(JsonPrimitive(false), task(report)["checkedDuringScan"])
                planner.requirePromotion(corrected, "explicit", checked.draftDigest)
                assertEquals(before, port.calls())
            }
        }
    }

    @Test fun `recovery reconciles an actual committed draft and preserves unknown interrupted checks without replay`() {
        for (committed in listOf(false, true)) {
            val port = DraftTestFixture.Port()
            JobStore(directory.resolve("interrupted-$committed")).use { store ->
                val first = worker(port, store); prepared(first); val p = DraftTestFixture.proposal()
                LookAheadPlanner(first, store, JobDrafts(first, store)).use { planner ->
                    declare(planner, p); planner.submit("current", "next-task", "interrupted", p)
                }
                if (committed) JobDrafts(first, store).validate("interrupted", p, "current")
                val key = "lookahead:queue:current"; val saved = store.get(key)!!.jsonObject
                val tasks = saved["tasks"]!!.jsonArray.map { JsonObject(it.jsonObject + ("state" to JsonPrimitive("CHECKING"))) }
                store.put(key, JsonObject(saved + ("tasks" to JsonArray(tasks))))
                val second = worker(port, store); val before = port.calls()
                LookAheadPlanner(second, store, JobDrafts(second, store)).use { planner ->
                    val state = if (committed) "STATIC_CHECKED" else "CHECK_OUTCOME_UNKNOWN"
                    assertEquals(JsonPrimitive(state), task(planner.report("current"))["state"])
                    planner.onRunning("current"); assertEquals(before, port.calls())
                }
            }
        }
    }

    @Test fun `promotion cannot bypass declared static binding but undeclared legacy jobs remain usable`() {
        val port = DraftTestFixture.Port()
        JobStore(directory.resolve("promotion")).use { store ->
            val worker = worker(port, store); DraftTestFixture.start(worker)
            val drafts = JobDrafts(worker, store)
            LookAheadPlanner(worker, store, drafts).use { planner ->
                val p = DraftTestFixture.proposal(); declare(planner, p)
                val legacy = DraftTestFixture.proposal("undeclared-legacy").let { original ->
                    val endpoint = original.materials.single().endpoint.copy(path = "/unrelated")
                    val raw = "GET /unrelated HTTP/1.1\r\nHost: fixture.invalid:8080\r\n\r\n"
                    val material = original.materials.single().copy(id = "unrelated-observation", endpoint = endpoint, request = raw, requestSha256 = digest(raw))
                    original.copy(materials = listOf(material), targetPolicy = listOf(TargetPermit(endpoint)),
                        variants = original.variants.map { it.copy(request = it.request.copy(endpoint = endpoint, request = raw, sourceId = material.id, sourceRequestSha256 = material.requestSha256)) })
                }
                planner.requirePromotion(legacy, null, null)
                assertEquals("LOOKAHEAD_BOUND_DRAFT_REQUIRED", assertThrows(JobRejected::class.java) { planner.requirePromotion(p, null, null) }.code)
                assertEquals("LOOKAHEAD_BOUND_DRAFT_REQUIRED", assertThrows(JobRejected::class.java) { planner.requirePromotion(p.copy(jobId = "renamed-bypass"), null, null) }.code)
                val relabelled = p.copy(jobId = "renamed-source-bypass", materials = p.materials.map { it.copy(id = "new-label") },
                    variants = p.variants.map { it.copy(request = it.request.copy(sourceId = "new-label")) })
                planner.requirePromotion(relabelled, null, null) // A separately declared source identity is not this queue's target.
                val unrelatedSameJob = legacy.copy(jobId = p.jobId)
                planner.requirePromotion(unrelatedSameJob, null, null)
                planner.submit("current", "next-task", "bound", p); await(planner, "STATIC_CHECKED")
                val digest = drafts.load("bound").draftDigest
                planner.requirePromotion(p, "bound", digest)
                for ((id, hash) in listOf("other" to digest, "bound" to "wrong")) {
                    assertEquals("LOOKAHEAD_BOUND_DRAFT_REQUIRED", assertThrows(JobRejected::class.java) { planner.requirePromotion(p, id, hash) }.code)
                }
                assertEquals("LOOKAHEAD_BOUND_DRAFT_REQUIRED", assertThrows(JobRejected::class.java) { planner.requirePromotion(p.copy(revision = 2), "bound", digest) }.code)
            }
        }
    }

    @Test fun `only successful formal registration consumes a bound task and historical consumed work does not gate another job`() {
        val port = DraftTestFixture.Port()
        JobStore(directory.resolve("consumed")).use { store ->
            val worker = worker(port, store); DraftTestFixture.start(worker)
            val drafts = JobDrafts(worker, store)
            LookAheadPlanner(worker, store, drafts).use { planner ->
                val p = DraftTestFixture.proposal(); declare(planner, p)
                planner.submit("current", "next-task", "consumed-draft", p); await(planner, "STATIC_CHECKED")
                val draft = drafts.load("consumed-draft")
                assertEquals("LOOKAHEAD_PROMOTION_NOT_REGISTERED", assertThrows(JobRejected::class.java) {
                    planner.recordPromotion(p, draft.draftId, draft.draftDigest, "not-registered")
                }.code)
                assertEquals("LOOKAHEAD_BOUND_DRAFT_REQUIRED", assertThrows(JobRejected::class.java) { planner.requirePromotion(p, null, null) }.code)
                port.completed = true; worker.poll("current")
                worker.registerDraft("formal-next", draft)
                val before = port.calls()
                planner.recordPromotion(p, draft.draftId, draft.draftDigest, "formal-next")
                planner.recordPromotion(p, draft.draftId, draft.draftDigest, "formal-next")
                val report = planner.report("current")
                assertEquals(JsonPrimitive("formal-next"), task(report)["promotedExecutionId"])
                assertEquals(JsonPrimitive("STATIC_CHECKED"), task(report)["state"])
                assertEquals(JsonPrimitive("ALL_DECLARED_DRAFTS_PROMOTED"), report["agentNextAction"])
                planner.requirePromotion(p, null, null)
                assertEquals(before, port.calls())
            }
        }
    }

    @Test fun `an old terminal job without a queue does not ask the agent to revive an earlier goal`() {
        val port = DraftTestFixture.Port()
        JobStore(directory.resolve("old-terminal")).use { store ->
            val worker = worker(port, store); DraftTestFixture.start(worker)
            port.completed = true; worker.poll("current")
            LookAheadPlanner(worker, store, JobDrafts(worker, store)).use { planner ->
                val before = port.calls(); val report = planner.report("current")
                assertEquals(JsonPrimitive(false), report["declared"])
                assertEquals(JsonPrimitive("NO_REGISTERED_NEXT_TARGET_WORK"), report["agentNextAction"])
                assertEquals(before, port.calls())
            }
        }
    }

    @Test fun `an unpromoted successful draft can be revised while preserving its immutable success and latest-only promotion binding`() {
        val port = DraftTestFixture.Port()
        JobStore(directory.resolve("revise-success")).use { store ->
            val worker = worker(port, store); DraftTestFixture.start(worker)
            val drafts = JobDrafts(worker, store)
            LookAheadPlanner(worker, store, drafts).use { planner ->
                val original = DraftTestFixture.proposal(); declare(planner, original)
                planner.submit("current", "next-task", "success-one", original)
                val first = await(planner, "STATIC_CHECKED"); val saved = drafts.load("success-one")
                val before = port.calls(); val current = worker.record("current"); val fence = store.get("fence")
                assertEquals("LOOKAHEAD_NEW_REVISION_REQUIRED", assertThrows(JobRejected::class.java) {
                    planner.submit("current", "next-task", "same-revision", original)
                }.code)
                assertEquals("LOOKAHEAD_DRAFT_ID_REUSED", assertThrows(JobRejected::class.java) {
                    planner.submit("current", "next-task", "success-one", original.copy(revision = 2))
                }.code)
                val revised = original.copy(revision = 2)
                synchronized(drafts) {
                    planner.submit("current", "next-task", "success-two", revised)
                    assertEquals(JsonPrimitive("CHECKING"), task(planner.report("current"))["state"])
                    assertEquals("LOOKAHEAD_CHECK_ALREADY_SUBMITTED", assertThrows(JobRejected::class.java) {
                        planner.submit("current", "next-task", "while-checking", revised.copy(revision = 3))
                    }.code)
                    assertEquals("LOOKAHEAD_BOUND_DRAFT_REQUIRED", assertThrows(JobRejected::class.java) {
                        planner.requirePromotion(original, saved.draftId, saved.draftDigest)
                    }.code)
                }
                val second = await(planner, "STATIC_CHECKED")
                val history = second["priorAttempts"]!!.jsonArray.single().jsonObject
                assertEquals(JsonPrimitive(saved.draftId), history["draftId"])
                assertEquals(JsonPrimitive(saved.draftDigest), history["draftDigest"])
                assertEquals(JsonPrimitive(fingerprint(original)), history["proposalDigest"])
                assertEquals(JsonPrimitive(1), history["revision"])
                assertEquals(first["state"], history["state"])
                assertEquals(first["checkedEpoch"], history["checkedEpoch"])
                assertEquals(first["checkedAuditId"], history["checkedAuditId"])
                assertEquals(JsonPrimitive(true), history["checkedDuringScan"])
                assertEquals(saved, drafts.load("success-one"))
                val latest = drafts.load("success-two")
                planner.requirePromotion(revised, latest.draftId, latest.draftDigest)
                assertEquals("LOOKAHEAD_BOUND_DRAFT_REQUIRED", assertThrows(JobRejected::class.java) {
                    planner.requirePromotion(original, saved.draftId, saved.draftDigest)
                }.code)
                assertEquals("LOOKAHEAD_DRAFT_ID_REUSED", assertThrows(JobRejected::class.java) {
                    planner.submit("current", "next-task", "success-one", revised.copy(revision = 3))
                }.code)
                assertEquals(before, port.calls()); assertEquals(current, worker.record("current")); assertEquals(fence, store.get("fence"))
                port.completed = true; worker.poll("current")
                val stable = task(planner.report("current"))
                assertEquals(stable, task(planner.submit("current", "next-task", latest.draftId, revised)))
                assertEquals(JsonPrimitive(true), stable["checkedDuringScan"])
                assertEquals(JsonPrimitive(false), stable["windowMissed"])
            }
        }
    }

    @Test fun `fresh macro collision can be corrected by binding a new successful revision after the parent window ends`() {
        val port = DraftTestFixture.Port().apply { current = LoginPreparationFixture.baseline }
        JobStore(directory.resolve("revise-after-collision")).use { store ->
            val worker = worker(port, store); DraftTestFixture.start(worker)
            val drafts = JobDrafts(worker, store)
            LookAheadPlanner(worker, store, drafts).use { planner ->
                val original = LoginPreparationFixture.proposal(); declare(planner, original)
                planner.submit("current", "next-task", "before-collision", original)
                val first = await(planner, "STATIC_CHECKED"); val old = drafts.load("before-collision")
                port.completed = true; worker.poll("current")
                val project = port.current.project
                val root = project["project_options"]!!.jsonObject
                val sessions = root["sessions"]!!.jsonObject
                val macroContainer = sessions["macros"] as? JsonObject ?: JsonObject(emptyMap())
                val collision = JsonObject(macroContainer + ("macros" to JsonArray(listOf(original.variants.single().settings.macros.first()))))
                port.current = port.current.copy(project = JsonObject(project + ("project_options" to JsonObject(root +
                    ("sessions" to JsonObject(sessions + ("macros" to collision)))))))
                val fresh = port.current
                assertEquals("MACRO_ID_COLLISION", assertThrows(JobRejected::class.java) {
                    planner.withPromotion(original, old.draftId, old.draftDigest, "rejected-next") {
                        worker.registerDraft("rejected-next", old)
                    }
                }.code)
                assertNull(store.get("execution:rejected-next")); assertNull(task(planner.report("current"))["promotedExecutionId"])
                assertEquals(JsonPrimitive(false), task(planner.report("current"))["promotionInProgress"])
                val settings = original.variants.single().settings
                val correctedSettings = settings.copy(
                    macros = JsonArray(settings.macros.map { value ->
                        val macro = value.jsonObject
                        JsonObject(macro + ("serial_number" to JsonPrimitive(macro["serial_number"]!!.jsonPrimitive.long + 100)))
                    }),
                    rules = JsonArray(settings.rules.map { value ->
                        val rule = value.jsonObject
                        JsonObject(rule + ("actions" to JsonArray(rule["actions"]!!.jsonArray.map { action ->
                            val fields = action.jsonObject
                            JsonObject(fields + ("macro_serial_number" to JsonPrimitive(fields["macro_serial_number"]!!.jsonPrimitive.long + 100)))
                        })))
                    }))
                val corrected = original.copy(revision = 2, variants = original.variants.map { it.copy(settings = correctedSettings) })
                val before = port.calls()
                val next = drafts.validate("after-collision", corrected, "current")
                val rebound = task(planner.submit("current", "next-task", next.draftId, corrected))
                assertEquals(JsonPrimitive("STATIC_CHECKED"), rebound["state"])
                assertEquals(JsonPrimitive(false), rebound["checkedDuringScan"])
                assertEquals(JsonPrimitive(true), rebound["windowMissed"])
                val history = rebound["priorAttempts"]!!.jsonArray.single().jsonObject
                assertEquals(JsonPrimitive(old.draftDigest), history["draftDigest"])
                assertEquals(first["checkedEpoch"], history["checkedEpoch"])
                assertEquals(first["checkedAuditId"], history["checkedAuditId"])
                assertEquals(JsonPrimitive(true), history["checkedDuringScan"])
                assertEquals(old, drafts.load(old.draftId)); assertEquals(before, port.calls())
                assertEquals("LOOKAHEAD_BOUND_DRAFT_REQUIRED", assertThrows(JobRejected::class.java) {
                    planner.requirePromotion(original, old.draftId, old.draftDigest)
                }.code)
                planner.withPromotion(corrected, next.draftId, next.draftDigest, "corrected-next") {
                    worker.registerDraft("corrected-next", next)
                }
                assertEquals(fresh, worker.plan("corrected-next").baseline)
                assertEquals(JsonPrimitive("corrected-next"), task(planner.report("current"))["promotedExecutionId"])
                val consumed = task(planner.report("current"))
                assertEquals(consumed, task(planner.submit("current", "next-task", next.draftId, corrected)))
                assertEquals("LOOKAHEAD_ALREADY_PROMOTED", assertThrows(JobRejected::class.java) {
                    planner.submit("current", "next-task", "after-consumption", corrected.copy(revision = 3))
                }.code)
                assertNull(store.get("approval:corrected-next:PREPARATION")); assertNull(store.get("approval:corrected-next:EXECUTION"))
                assertNull(store.get("validation:corrected-next")); assertEquals(fresh, port.current)
            }
        }
    }

    @Test fun `promotion reservation blocks replacement without holding the planning monitor and releases on registration failure`() {
        val port = DraftTestFixture.Port(); val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val threads = Executors.newSingleThreadExecutor()
        JobStore(directory.resolve("promotion-race")).use { store ->
            val worker = worker(port, store); DraftTestFixture.start(worker)
            val drafts = JobDrafts(worker, store)
            LookAheadPlanner(worker, store, drafts).use { planner ->
                val first = DraftTestFixture.proposal("one"); val second = DraftTestFixture.proposal("two")
                planner.declare("current", JsonArray(listOf(declaration(first, "one"), declaration(second, "two"))).toString())
                planner.submit("current", "one", "reserved-one", first); await(planner, "STATIC_CHECKED", "one")
                val saved = drafts.load("reserved-one"); val before = port.calls(); val fence = store.get("fence")
                val registration = threads.submit<Any> {
                    planner.withPromotion(first, saved.draftId, saved.draftDigest, "waiting-registration") {
                        entered.countDown(); check(release.await(5, TimeUnit.SECONDS))
                        throw JobRejected("FIXTURE_PROMOTION_REJECTED")
                    }
                }
                try {
                    assertTrue(entered.await(2, TimeUnit.SECONDS))
                    assertEquals(JsonPrimitive(true), task(planner.report("current"), "one")["promotionInProgress"])
                    assertEquals("LOOKAHEAD_PROMOTION_IN_PROGRESS", assertThrows(JobRejected::class.java) {
                        planner.submit("current", "one", "blocked-revision", first.copy(revision = 2))
                    }.code)
                    assertEquals("LOOKAHEAD_PROMOTION_IN_PROGRESS", assertThrows(JobRejected::class.java) {
                        planner.information("current", "one", listOf("Attempted concurrent mutation"))
                    }.code)
                    assertEquals("LOOKAHEAD_PROMOTION_IN_PROGRESS", assertThrows(JobRejected::class.java) {
                        planner.withPromotion(first, saved.draftId, saved.draftDigest, "another-registration") { error("must not register") }
                    }.code)
                    assertEquals(JsonPrimitive("STATIC_CHECKED"), task(planner.submit("current", "one", saved.draftId, first), "one")["state"])
                    planner.submit("current", "two", "independent-two", second)
                    await(planner, "STATIC_CHECKED", "two")
                    assertFalse(registration.isDone)
                } finally { release.countDown() }
                val rejected = assertThrows(java.util.concurrent.ExecutionException::class.java) { registration.get(3, TimeUnit.SECONDS) }
                assertEquals("FIXTURE_PROMOTION_REJECTED", (rejected.cause as JobRejected).code)
                assertEquals(JsonPrimitive(false), task(planner.report("current"), "one")["promotionInProgress"])
                assertNull(task(planner.report("current"), "one")["promotedExecutionId"])
                planner.submit("current", "one", "after-failure", first.copy(revision = 2))
                await(planner, "STATIC_CHECKED", "one")
                assertEquals(before, port.calls()); assertEquals(fence, store.get("fence"))
            }
        }
        threads.shutdownNow()
    }

    @Test fun `a committed formal registration remains consumed for revision checks even if its queue receipt was not written`() {
        val port = DraftTestFixture.Port()
        JobStore(directory.resolve("promotion-receipt-gap")).use { store ->
            val worker = worker(port, store); DraftTestFixture.start(worker)
            val drafts = JobDrafts(worker, store)
            LookAheadPlanner(worker, store, drafts).use { planner ->
                val original = DraftTestFixture.proposal(); declare(planner, original)
                planner.submit("current", "next-task", "receipt-gap", original); await(planner, "STATIC_CHECKED")
                val saved = drafts.load("receipt-gap")
                port.completed = true; worker.poll("current")
                assertEquals("FIXTURE_AFTER_REGISTRATION", assertThrows(JobRejected::class.java) {
                    planner.withPromotion(original, saved.draftId, saved.draftDigest, "committed-next") {
                        worker.registerDraft("committed-next", saved)
                        throw JobRejected("FIXTURE_AFTER_REGISTRATION")
                    }
                }.code)
                assertEquals("STATIC_VALIDATED", worker.record("committed-next").state)
                val withoutReceipt = task(planner.report("current"))
                assertNull(withoutReceipt["promotedExecutionId"])
                assertEquals(JsonPrimitive(false), withoutReceipt["promotionInProgress"])
                val before = port.calls()
                assertEquals("LOOKAHEAD_ALREADY_PROMOTED", assertThrows(JobRejected::class.java) {
                    planner.submit("current", "next-task", "must-not-revise", original.copy(revision = 2))
                }.code)
                assertEquals("LOOKAHEAD_ALREADY_PROMOTED", assertThrows(JobRejected::class.java) {
                    planner.withPromotion(original, saved.draftId, saved.draftDigest, "duplicate-next") { error("must not register") }
                }.code)
                assertEquals(withoutReceipt, task(planner.submit("current", "next-task", saved.draftId, original)))
                planner.recordPromotion(original, saved.draftId, saved.draftDigest, "committed-next")
                assertEquals(JsonPrimitive("committed-next"), task(planner.report("current"))["promotedExecutionId"])
                assertEquals(before, port.calls()); assertNull(store.get("execution:duplicate-next"))
                assertEquals(saved, drafts.load(saved.draftId))
            }
        }
    }

    @Test fun `static planning does not acquire a worker monitor held by another workflow operation`() {
        val port = DraftTestFixture.Port(); val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val threads = Executors.newSingleThreadExecutor()
        JobStore(directory.resolve("monitor")).use { store ->
            val worker = worker(port, store); DraftTestFixture.start(worker)
            LookAheadPlanner(worker, store, JobDrafts(worker, store)).use { planner ->
                val held = threads.submit { synchronized(worker) { entered.countDown(); check(release.await(5, TimeUnit.SECONDS)) } }
                try {
                    assertTrue(entered.await(2, TimeUnit.SECONDS)); val before = port.calls(); val p = DraftTestFixture.proposal()
                    declare(planner, p); planner.submit("current", "next-task", "independent-monitor", p)
                    await(planner, "STATIC_CHECKED"); assertFalse(held.isDone); assertEquals(before, port.calls())
                } finally { release.countDown(); held.get(3, TimeUnit.SECONDS); threads.shutdownNow() }
            }
        }
    }
}
