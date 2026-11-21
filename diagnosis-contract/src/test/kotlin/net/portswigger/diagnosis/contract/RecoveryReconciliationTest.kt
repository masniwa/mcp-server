package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/** Anonymous saved-setting fixtures: no production HTTP, accounts, IDs or runtime data. */
class RecoveryReconciliationTest {
    @Test fun journaledBeforeApplyDistinguishesPreservedNonOwnedEditsFromUnattributedEffects() {
        val baseline=snapshot(obj("""{"human":1,"deleted":true}"""))
        val approved=baseline
        val before=baseline.copy(project=obj("""{"human":2}"""))
        val applied=before
        val observed=recoveryEvidenceDifferences(baseline,approved,applied,applied,before)
        assertTrue(observed.all { it.disposition==RecoveryDisposition.KEEP })
        assertEquals(recoverySettings(applied),selectedRecoveryCandidate(recoverySettings(applied),observed,emptyMap()))
        assertTrue(recoveryEvidenceDifferences(baseline,approved,applied,applied).any { it.disposition==RecoveryDisposition.UNKNOWN_OWNER })
        val unexpected=applied.copy(project=obj("""{"human":3}"""))
        assertTrue(recoveryEvidenceDifferences(baseline,approved,unexpected,unexpected,before).any { it.disposition==RecoveryDisposition.UNKNOWN_OWNER })
        assertTrue(recoveryEvidenceDifferences(baseline,approved,applied,applied,before.copy(instanceId="other")).any { it.disposition==RecoveryDisposition.UNKNOWN_OWNER })
        val inherited=snapshot(obj("""{"sessions":{"session_handling_rules":{"rules":[{"description":"human-scope","enabled":false,"url_scope_advanced_mode":false,"include_in_scope":[{"prefix":"https://fixture.invalid/api?mode=ReadItem"}]}]}}}"""))
        val native=inherited.copy(project=obj(inherited.project.toString().replace("ReadItem","readitem")))
        assertTrue(recoveryEvidenceDifferences(inherited,inherited,native,native,inherited).all { it.disposition==RecoveryDisposition.KEEP })
        val changedHost=native.copy(project=obj(native.project.toString().replace("fixture.invalid","other.invalid")))
        assertTrue(recoveryEvidenceDifferences(inherited,inherited,changedHost,changedHost,inherited).any { it.disposition==RecoveryDisposition.UNKNOWN_OWNER })
    }
    @Test fun historicalUnknownApplyArtifactDoesNotBecomeCurrentOwnershipConflictAfterItIsAbsent() {
        val baseline=snapshot(cph=obj("{}"))
        val applied=snapshot(cph=obj("""{"unattributed":{"enabled":true}}"""))
        val diff=recoveryEvidenceDifferences(baseline,baseline,applied,baseline)
        assertEquals(1,diff.size);assertEquals(RecoveryDisposition.KEEP,diff.single().disposition)
        assertNotNull(diff.single().applied)
        assertEquals(recoverySettings(baseline),selectedRecoveryCandidate(recoverySettings(baseline),diff,emptyMap()))
        val stillPresent=recoveryEvidenceDifferences(baseline,baseline,applied,applied)
        assertEquals(RecoveryDisposition.UNKNOWN_OWNER,stillPresent.single().disposition)
    }

    @Test fun createdNativeRuleReadbackDifferenceCanBeRemovedWithoutTouchingHumanRule() {
        val baseline=snapshot(obj("{}"))
        val approved=snapshot(obj("""{"sessions":{"session_handling_rules":{"rules":[{"description":"job:fixture:temporary","enabled":true,"include_in_scope":[{"prefix":"https://fixture.invalid/api?mode=ReadItem"}]}]}}}"""))
        val native=snapshot(obj("""{"sessions":{"session_handling_rules":{"rules":[{"description":"human-added","enabled":false},{"description":"job:fixture:temporary","enabled":true,"include_in_scope":[{"prefix":"https://fixture.invalid/api?mode=readitem"}]}]}}}"""))
        val diff=recoveryEvidenceDifferences(baseline,approved,approved,native)
        val owned=diff.single { it.path.endsWith("/description:job:fixture:temporary") }
        assertEquals(RecoveryDisposition.CONFLICT_REVIEW,owned.disposition)
        val selected=selectedRecoveryCandidate(recoverySettings(native),diff,mapOf(owned.path to "RESTORE_BASELINE"))
        val target=recoveryCandidateSnapshot(native,selected,baseline)
        val rules=target.project.getValue("sessions").jsonObject.getValue("session_handling_rules").jsonObject.getValue("rules").jsonArray
        assertEquals(1,rules.size);assertEquals(JsonPrimitive("human-added"),rules.single().jsonObject["description"])
        assertTrue(recoveryProjectPatch(native.project,target.project).containsKey("sessions"))
    }

    @Test fun missingSavedDefinitionsRestoreDisabledWithOnlyNeededCachedSources() {
        val saved=snapshot(cph=obj("""{"source":{"enabled":true,"marker":"saved"},"dependent":{"enabled":true,"dynamic_checkbox":true,"extract_choice_index":2,"cached_selection":"source"},"unused":{"enabled":false}}"""))
        val current=snapshot(cph=obj("""{"human":{"enabled":false}}"""))
        val diff=recoveryEvidenceDifferences(saved,saved,saved,current)
        val selected=selectedRecoveryCandidate(recoverySettings(current),diff,mapOf("/cph/dependent" to "RESTORE_BASELINE"))
        val candidate=recoveryCandidateSnapshot(current,selected,saved)
        assertEquals(setOf("human","source","dependent"),candidate.cph.keys)
        assertEquals(JsonPrimitive(false),candidate.cph.getValue("source").jsonObject["enabled"])
        assertEquals(JsonPrimitive(false),candidate.cph.getValue("dependent").jsonObject["enabled"])
        assertTrue(candidate.cphOrder.indexOf("source")<candidate.cphOrder.indexOf("dependent"))
        assertEquals(current.cph.getValue("human"),candidate.cph["human"])
        val conflict=current.copy(cph=JsonObject(current.cph+("source" to obj("""{"enabled":false,"marker":"human"}"""))),cphOrder=listOf("source","human"))
        val conflictDiff=recoveryEvidenceDifferences(saved,saved,saved,conflict)
        val conflictSettings=selectedRecoveryCandidate(recoverySettings(conflict),conflictDiff,mapOf("/cph/dependent" to "RESTORE_BASELINE"))
        assertEquals("CPH_RESTORE_DEPENDENCY_CONFLICT",assertThrows(JobRejected::class.java) {
            recoveryCandidateSnapshot(conflict,conflictSettings,saved)
        }.code)
    }

    @Test fun legacyMissingReadbackDoesNotInventHistoryOrBlockProvenOwnedValues() {
        val baseline=snapshot(cph=obj("""{"auth":{"enabled":false}}"""))
        val approved=snapshot(cph=obj("""{"auth":{"enabled":true}}"""))
        val current=approved
        val diff=recoveryEvidenceDifferences(baseline,approved,null,current)
        val restored=selectedRecoveryCandidate(recoverySettings(current),diff,emptyMap())
        assertEquals(JsonPrimitive(false),restored.getValue("cph").jsonObject.getValue("auth").jsonObject["enabled"])
        val mixed=current.copy(cph=JsonObject(current.cph+("unattributed" to obj("""{"enabled":false}"""))),cphOrder=current.cphOrder+"unattributed")
        val uncertain=recoveryEvidenceDifferences(baseline,approved,null,mixed)
        assertTrue(uncertain.any { it.disposition==RecoveryDisposition.UNKNOWN_OWNER })
        assertThrows(JobRejected::class.java) { selectedRecoveryCandidate(recoverySettings(mixed),uncertain,emptyMap()) }
    }

    @Test fun `restoration destination preserves approved retained authentication`() {
        val baseline=obj("""{"cph":{"auth":{"enabled":false,"value":"old"}},"human":1}""")
        val approved=obj("""{"cph":{"auth":{"enabled":true,"value":"new"}},"human":1}""")
        val current=obj("""{"cph":{"auth":{"enabled":true,"value":"new"}},"human":2}""")
        val retained=obj("""{"cph":{"auth":{"enabled":false,"value":"new"}},"human":1}""")
        val diff=recoveryDestinations(recoveryDifferences(baseline,approved,approved,current),retained)
        assertEquals(obj("""{"cph":{"auth":{"enabled":false,"value":"new"}},"human":2}"""),
            selectedRecoveryCandidate(current,diff,emptyMap()))
    }

    private fun obj(raw:String)=Json.parseToJsonElement(raw).jsonObject
    private fun snapshot(project:JsonObject= obj("{}"),cph:JsonObject=obj("{}")) =
        BurpSnapshot("process",project,cph,cph.keys.toList(),emptySet(),projectMarker="saved-project")
    private fun observation()=obj("""{"activeTrackedMcpSends":0,"captureHealth":"NO_WINDOW_LOSS_OBSERVED","cphActivity":{"active":{"http_handler":0,"helper_send":0}}}""")

    @Test fun `historical missing responses and errors never imply current activity`() {
        val facts=observation()
        for(count in listOf(0,4,200)) assertEquals(emptyList<String>(),recoveryActivityBlockers(JsonObject(facts+mapOf(
            "noResponseObserved" to JsonPrimitive(count),"historicalCaptureErrors" to JsonPrimitive(count)))))
        assertEquals(recoveryTrafficFence(facts),recoveryTrafficFence(JsonObject(facts+mapOf(
            "throughId" to JsonPrimitive(200),"noResponseObserved" to JsonPrimitive(4)))))
    }
    @Test fun `current send loss and absent CPH evidence block independently`() {
        val facts=JsonObject(observation()+mapOf("activeTrackedMcpSends" to JsonPrimitive(1),
            "captureHealth" to JsonPrimitive("WINDOW_INCOMPLETE"),"cphActivity" to JsonNull))
        assertEquals(3,recoveryActivityBlockers(facts).size)
        assertEquals(3,recoveryActivityBlockers(obj("{}" )).size)
    }
    @Test fun `owned scalar conflict requires explicit review without changing original observations`() {
        val base=obj("""{"scope":"planned-before","human":1}""")
        val approved=obj("""{"scope":"planned-after","human":1}""")
        val current=obj("""{"scope":"native-observed","human":2}""")
        // The unrelated edit occurred after readback, not as an unattributed apply effect.
        val diff=recoveryDifferences(base,approved,approved,current)
        assertThrows(JobRejected::class.java) { selectedRecoveryCandidate(current,diff,emptyMap()) }
        assertEquals(obj("""{"scope":"planned-before","human":2}"""),
            selectedRecoveryCandidate(current,diff,mapOf("/scope" to "RESTORE_BASELINE")))
        assertEquals("native-observed",current.getValue("scope").jsonPrimitive.content)
        assertThrows(JobRejected::class.java) { selectedRecoveryCandidate(current,diff,mapOf("/scope" to "KEEP_CURRENT","/human" to "RESTORE_BASELINE")) }
    }
    @Test fun `unknown partial import ownership cannot be converted into a keep decision`() {
        val base=obj("""{"cph":{}}""");val current=obj("""{"cph":{"unfinished":{"enabled":true}}}""")
        val diff=recoveryDifferences(base,base,current,current)
        assertEquals("AMBIGUOUS_OWNERSHIP",assertThrows(JobRejected::class.java) {
            selectedRecoveryCandidate(current,diff,mapOf("/cph/unfinished" to "KEEP_CURRENT"))
        }.code)
    }
    @Test fun `native macro identities preserve human change deletion addition and relative order`() {
        fun project(items:String)=obj("""{"sessions":{"macros":{"macros":$items}}}""")
        val base=snapshot(project("""[{"serial_number":9007199254740993,"description":"human-a"},{"serial_number":2,"description":"human-b"}]"""))
        val approved=snapshot(project("""[{"serial_number":9007199254740993,"description":"human-a"},{"serial_number":2,"description":"human-b"},{"serial_number":3,"description":"job:sample:temporary"}]"""))
        val current=snapshot(project("""[{"serial_number":4,"description":"new-human"},{"serial_number":9007199254740993,"description":"edited-human"},{"serial_number":3,"description":"job:sample:temporary"}]"""))
        val view=recoverySettings(current)
        val diff=recoveryDifferences(recoverySettings(base),recoverySettings(approved),recoverySettings(approved),view)
        val target=recoveryCandidateSnapshot(current,selectedRecoveryCandidate(view,diff,emptyMap()),base)
        assertEquals(project("""[{"serial_number":4,"description":"new-human"},{"serial_number":9007199254740993,"description":"edited-human"}]"""),target.project)
        assertTrue(recoveryProjectPatch(current.project,target.project).containsKey("sessions"))
    }
    @Test fun `mixed missing saved CPH and new definitions preserve current and require explicit restore`() {
        val saved=snapshot(cph=obj("""{"saved":{"enabled":false},"deleted":{"enabled":false}}"""))
        val current=snapshot(cph=obj("""{"new":{"enabled":false}}"""))
        val diff=recoveryDifferences(recoverySettings(saved),recoverySettings(saved),recoverySettings(saved),recoverySettings(current))
        val selected=selectedRecoveryCandidate(recoverySettings(current),diff,mapOf("/cph/saved" to "RESTORE_BASELINE"))
        val target=recoveryCandidateSnapshot(current,selected,saved)
        assertEquals(setOf("saved","new"),target.cph.keys)
        assertFalse("deleted" in target.cph)
    }
    @Test fun `partial project patch omits unrelated sections and refuses unverified removal`() {
        val current=obj("""{"owned":{"enabled":true},"human":{"setting":2}}""")
        val target=obj("""{"owned":{"enabled":false},"human":{"setting":2}}""")
        assertEquals(obj("""{"owned":{"enabled":false}}"""),recoveryProjectPatch(current,target))
        assertThrows(JobRejected::class.java) { recoveryProjectPatch(current,obj("{}")) }
    }
    @Test fun `selection wire defaults preserve old decoding and unknown fields are rejected`() {
        assertTrue(jobJson.decodeFromString<RecoverySelection>("""{"snapshotDigest":"observed"}""").decisions.isEmpty())
        assertThrows(Exception::class.java) { jobJson.decodeFromString<RecoverySelection>("""{"snapshotDigest":"observed","approved":true}""") }
    }
}
