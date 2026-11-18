package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class OncePreparationSerializationTest {
    @Test fun `legacy variant serialization retains the exact canonical digest without new empty safeguards`() {
        val old=jobJson.parseToJsonElement("""{"id":"reflection","kind":"REFLECTION","verificationSourceId":null,"request":{"endpoint":{"scheme":"http","host":"compat.fixture.invalid","port":80,"path":"/"},"request":"GET / HTTP/1.1\r\nHost: compat.fixture.invalid\r\n\r\n","sourceId":"observed","sourceRequestSha256":"observed-digest","startOptions":{}},"settings":{"macros":[],"rules":[],"cph":{},"cphOrder":[],"targetScope":null,"macroPreparations":[]},"requiredBranches":["normal"],"branchSetup":{}}""")
        val variant=jobJson.decodeFromJsonElement<ScanVariant>(old)
        assertTrue(variant.preparationOnce.isEmpty());assertTrue(variant.inputExclusions.isEmpty())
        assertEquals(old,jobJson.encodeToJsonElement(variant));assertEquals(digest(canonical(old)),fingerprint(variant))
    }
    @Test fun `legacy validation reports retain the exact digest used by stored approvals and recovery`() {
        val old=jobJson.parseToJsonElement("""{"planDigest":"legacy-plan","probes":[],"completedAt":1,"restored":true,"residualCphTabs":[]}""")
        val report=jobJson.decodeFromJsonElement<ValidationReport>(old)
        assertTrue(report.preparationOnce.isEmpty())
        assertEquals(old,jobJson.encodeToJsonElement(report));assertEquals(digest(canonical(old)),fingerprint(report))
    }
    @Test fun `nonempty once-only lists participate in proposal and validation fingerprints`() {
        val endpoint=Endpoint("http","compat.fixture.invalid",80,"/")
        val request=RequestPlan(endpoint,"GET / HTTP/1.1\r\nHost: compat.fixture.invalid\r\n\r\n","observed","observed-digest")
        val variant=ScanVariant("reflection","REFLECTION",request=request,settings=SettingsPlan())
        assertNotEquals(fingerprint(variant),fingerprint(variant.copy(preparationOnce=listOf(request))))
        val report=ValidationReport("plan",emptyList(),1,true,emptyList())
        val evidence=PreparationEvidence("reflection",0,"settings","HTTP/1.1 204 No Content\r\n\r\n",JsonObject(emptyMap()),1)
        assertNotEquals(fingerprint(report),fingerprint(report.copy(preparationOnce=listOf(evidence))))
    }
}
