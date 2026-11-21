package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class RecoveryDiffTest {
    private fun json(value: String) = Json.parseToJsonElement(value).jsonObject

    @Test fun `restore owned field while preserving human deletion and new field`() {
        val base = json("""{"owned":false,"human":1,"deleted":true}""")
        val approved = json("""{"owned":true,"human":1,"deleted":true}""")
        val current = json("""{"owned":true,"human":2,"added":3}""")
        val diff = recoveryDifferences(base, approved, approved, current)
        assertEquals(4, diff.size)
        assertEquals(RecoveryDisposition.RESTORE_OWNED, diff.single { it.path == "/owned" }.disposition)
        assertEquals(json("""{"owned":false,"human":2,"added":3}"""), recoveryRestoreCandidate(current, diff))
    }

    @Test fun `unknown readback and same field conflict are all reported`() {
        val base = json("""{"scope":"A","other":1}""")
        val approved = json("""{"scope":"B","other":1}""")
        val applied = json("""{"scope":"b","other":2}""")
        val diff = recoveryDifferences(base, approved, applied, applied)
        assertEquals(setOf(RecoveryDisposition.CONFLICT_REVIEW, RecoveryDisposition.UNKNOWN_OWNER),
            diff.map { it.disposition }.toSet())
        assertThrows(JobRejected::class.java) { recoveryRestoreCandidate(applied, diff) }
    }

    @Test fun `explicit null missing object arrays and escaped keys retain distinct identities`() {
        val base = json("""{"a/b~c":null,"array":[1,2]}""")
        val approved = json("""{"a/b~c":1,"array":[1,2],"object":{"enabled":true}}""")
        val diff = recoveryDifferences(base, approved, approved, approved)
        assertTrue(diff.any { it.path == "/a~1b~0c" && it.baseline == JsonNull })
        assertTrue(diff.any { it.path == "/object" && it.baseline == null })
        assertEquals(base, recoveryRestoreCandidate(approved, diff))
        val changed = json("""{"a/b~c":1,"array":[2,1],"object":{"enabled":true}}""")
        assertEquals(RecoveryDisposition.KEEP,
            recoveryDifferences(base, approved, approved, changed).single { it.path == "/array" }.disposition)
    }

    @Test fun `stale owned value cannot be overwritten using old evaluation`() {
        val base = json("""{"owned":0}""")
        val approved = json("""{"owned":1}""")
        val diff = recoveryDifferences(base, approved, approved, approved)
        assertThrows(JobRejected::class.java) { recoveryRestoreCandidate(json("""{"owned":2}"""), diff) }
        assertEquals(base, recoveryRestoreCandidate(base, recoveryDifferences(base, approved, approved, base)))
    }
}