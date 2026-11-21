package net.portswigger.mcp.execution

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import javax.swing.SwingUtilities

class UiProjectMutationTest {
    private fun obj(raw:String)=Json.parseToJsonElement(raw).jsonObject
    @Test fun compareImportAndReadbackRunOnUiThreadWithOnlyChangedSections() {
        val before=obj("""{"sessions":{"macros":{"macros":[{"serial_number":1,"description":"human"}]}},"human":{"view":2}}""")
        val target=obj("""{"sessions":{"macros":{"macros":[{"serial_number":1,"description":"human"},{"serial_number":2,"description":"owned"}]}},"human":{"view":2}}""")
        var current=before;var reads=0;var writes=0
        val port=UiProjectMutation({ assertTrue(SwingUtilities.isEventDispatchThread());reads++;current },{ patch ->
            assertTrue(SwingUtilities.isEventDispatchThread());writes++
            assertFalse("human" in patch);assertEquals(target.getValue("sessions"),patch["sessions"])
            current=target
        })
        assertEquals(target,port.apply(before,target));assertEquals(2,reads);assertEquals(1,writes)
    }
    @Test fun humanEditQueuedBeforeMutationPreventsImport() {
        val before=obj("""{"owned":false,"human":1}""")
        var current=before;var writes=0
        SwingUtilities.invokeAndWait { current=obj("""{"owned":false,"human":2}""") }
        val port=UiProjectMutation({ current },{ writes++ })
        assertEquals("PROJECT_CHANGED_BEFORE_IMPORT",assertThrows(JobRejected::class.java) {
            port.apply(before,obj("""{"owned":true,"human":1}"""))
        }.code)
        assertEquals(0,writes);assertEquals(JsonPrimitive(2),current["human"])
    }
    @Test fun nativeUnexpectedReadbackRefusesAndDoesNotRetry() {
        var current=obj("""{"owned":false}""");var writes=0
        val port=UiProjectMutation({ current },{ writes++;current=obj("""{"owned":"unexpected"}""") })
        assertEquals("PROJECT_IMPORT_READBACK_CHANGED",assertThrows(JobRejected::class.java) {
            port.apply(current,obj("""{"owned":true}"""))
        }.code)
        assertEquals(1,writes)
    }
    @Test fun alreadyOnUiThreadDoesNotDeadlockAndFailedImportRemainsFailed() {
        val before=obj("""{"owned":false}""")
        var writes=0
        SwingUtilities.invokeAndWait {
            val port=UiProjectMutation({ before },{ writes++;throw IllegalStateException("import failed") })
            assertThrows(IllegalStateException::class.java) { port.apply(before,obj("""{"owned":true}""")) }
        }
        assertEquals(1,writes)
    }
}