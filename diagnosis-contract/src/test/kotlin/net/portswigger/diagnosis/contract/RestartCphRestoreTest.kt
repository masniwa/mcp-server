package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class RestartCphRestoreTest {
    private val options=digest("options")
    private val marker="12345678-1234-1234-1234-123456789abc"
    private val saved=BurpSnapshot("old",buildJsonObject { put("project_options",buildJsonObject {}) },buildJsonObject {
        put("job:old:source",buildJsonObject { put("enabled",false) })
        put("job:old:dependent",buildJsonObject { put("enabled",false);put("cached_selection","job:old:source") })
        put("job:other:unused",buildJsonObject { put("enabled",false) })
        put(options,buildJsonObject { put("verbosity",3) })
    },listOf("job:old:source","job:old:dependent","job:other:unused",options),emptySet(),projectMarker=marker)
    private val current=saved.copy(instanceId="new",cph=buildJsonObject { put(options,saved.cph.getValue(options)) },cphOrder=listOf(options))

    @Test fun `selected disabled dependency is restored in saved order without unrelated definitions`() {
        val (target,names)=selectRestartCphRestore(saved,current,setOf("job:old:dependent"))
        assertEquals(setOf("job:old:source","job:old:dependent"),names)
        assertEquals(listOf("job:old:source","job:old:dependent",options),target.cphOrder)
        assertFalse("job:other:unused" in target.cph)
        assertEquals(current.project,target.project)
    }
    @Test fun `different Project unknown CPH and enabled definitions are refused`() {
        val cases=listOf(
            current.copy(projectMarker="different"),
            current.copy(instanceId=saved.instanceId),
            current.copy(project=buildJsonObject { put("other",true) }),
            current.copy(cph=JsonObject(current.cph+("unowned" to buildJsonObject { put("enabled",false) })),cphOrder=listOf("unowned",options)),
            current.copy(cph=buildJsonObject { put(options,buildJsonObject { put("verbosity",4) }) })
        )
        cases.forEach { candidate -> assertThrows(JobRejected::class.java) {
            selectRestartCphRestore(saved,candidate,setOf("job:old:dependent"))
        } }
        val enabled=saved.copy(cph=JsonObject(saved.cph+("job:old:dependent" to buildJsonObject { put("enabled",true) })))
        assertThrows(JobRejected::class.java) { selectRestartCphRestore(enabled,current,setOf("job:old:dependent")) }
    }
}
