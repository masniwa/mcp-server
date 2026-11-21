package net.portswigger.mcp.jobs

import net.portswigger.diagnosis.contract.BurpSnapshot
import net.portswigger.diagnosis.contract.comparableNativeCollections
import org.junit.jupiter.api.Assertions.assertEquals

/** Only known empty native collection wrappers differ; every other snapshot field stays exact. */
internal fun assertNativeSnapshotEquals(expected:BurpSnapshot,actual:BurpSnapshot) {
    assertEquals(expected.copy(project=comparableNativeCollections(expected.project)),
        actual.copy(project=comparableNativeCollections(actual.project)))
}
