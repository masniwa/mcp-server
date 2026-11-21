package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import java.nio.file.Files
import java.nio.file.FileAlreadyExistsException
import java.util.Base64

class PayloadEvidenceStoreTest {
    @TempDir lateinit var root: Path
    @Test fun `scanner baseline is immutable and tampering prevents comparisons`() {
        val dir = root.resolve("baseline")
        val store = PayloadEvidenceStore.create(dir, plan())
        assertNull(store.readBaseline())
        store.recordBaseline(PayloadExchange("request".toByteArray(), "HTTP/1.1 200 OK\r\n\r\nnormal".toByteArray(), 200))
        val first = store.readBaseline()
        store.recordBaseline(PayloadExchange("other".toByteArray(), null, null))
        assertEquals(first, store.readBaseline())
        Files.writeString(dir.resolve("baseline.json"), Files.readString(dir.resolve("baseline.json")).replace("200", "500"))
        assertThrows(IllegalArgumentException::class.java) { store.readBaseline() }
    }
    private fun plan() = PayloadWirePlan.create("x=1".toByteArray(), PayloadProfileCatalog("a".repeat(64),
        listOf(ProfilePayload("p1", "replace", "light", "2", listOf("query")))), "light", listOf(PayloadWirePosition("x", "query", 2, 3, 0, 1)))

    @Test fun `executed candidate roundtrips binary wire evidence and source identities`() {
        val plan = plan()
        val store = PayloadEvidenceStore.create(root.resolve("run"), plan)
        val run = PayloadExecution(plan)
        val response = byteArrayOf(0, -1, 10, 13)
        run.execute({true}, { PayloadExchange(it, response, 200) }, store::record)
        val read = store.read(0)
        assertArrayEquals("x=2".toByteArray(), Base64.getDecoder().decode(read.requestBase64))
        assertArrayEquals(response, Base64.getDecoder().decode(read.responseBase64))
        assertEquals("p1", read.item.payloadId)
        assertEquals(plan.sourceSha256, Files.readString(root.resolve("run/source.sha256")))
        assertEquals(plan.requestSha256, Files.readString(root.resolve("run/request.sha256")))
        assertTrue(run.allCandidatesRecorded())
    }

    @Test fun `existing run directories cannot be overwritten`() {
        PayloadEvidenceStore.create(root.resolve("run"), plan())
        assertThrows(FileAlreadyExistsException::class.java) { PayloadEvidenceStore.create(root.resolve("run"), plan()) }
    }

    @Test fun `post macro evidence preserves diagnostic input separately from selected exchange`() {
        val plan = plan()
        val store = PayloadEvidenceStore.create(root.resolve("stored"), plan)
        val run = PayloadExecution(plan)
        val selectedRequest = "GET /stored HTTP/1.1\r\n\r\n".toByteArray()
        val selectedResponse = "stored value 2".toByteArray()
        run.execute({true}, { input -> PayloadExchange(selectedRequest, selectedResponse, 200, input) }, store::record)
        val evidence = store.read(0, run.snapshot().single())
        assertArrayEquals("x=2".toByteArray(), Base64.getDecoder().decode(evidence.submittedRequestBase64))
        assertArrayEquals(selectedRequest, Base64.getDecoder().decode(evidence.requestBase64))
        assertArrayEquals(selectedResponse, Base64.getDecoder().decode(evidence.responseBase64))
        assertNotEquals(evidence.item.requestSha256, evidence.item.submittedRequestSha256)
        assertThrows(IllegalArgumentException::class.java) {
            store.record(evidence.item, PayloadExchange(selectedRequest, selectedResponse, 200, "x=wrong".toByteArray()))
        }
    }

    @Test fun `unchanged wire hashes do not validate altered evidence identity or state`() {
        val plan = plan()
        val directory = root.resolve("ledger")
        val store = PayloadEvidenceStore.create(directory, plan)
        val run = PayloadExecution(plan)
        run.execute({true}, { PayloadExchange(it, "response".toByteArray(), 200) }, store::record)
        val expected = run.snapshot().single()
        assertEquals(expected, store.read(0, expected).item)
        val path = directory.resolve("0.json")
        val original = Files.readString(path)
        for ((before, after) in listOf(
            "\"payloadId\":\"p1\"" to "\"payloadId\":\"other\"",
            "\"state\":\"RESPONSE_RECEIVED\"" to "\"state\":\"NO_RESPONSE\"",
            "\"statusCode\":200" to "\"statusCode\":403"
        )) {
            assertTrue(original.contains(before))
            Files.writeString(path, original.replace(before, after))
            // Wire hashes alone would pass; the committed record must also match.
            assertThrows(IllegalArgumentException::class.java) { store.read(0) }
            assertThrows(IllegalArgumentException::class.java) { store.read(0, expected) }
        }
        Files.writeString(path, original)
        assertEquals(expected, store.read(0, expected).item)
    }

    @Test fun `corrupt or mismatched evidence fails verification`() {
        val plan = plan()
        val store = PayloadEvidenceStore.create(root.resolve("run"), plan)
        val run = PayloadExecution(plan)
        run.execute({true}, { PayloadExchange(it, null, null) }, store::record)
        val existing = store.read(0)
        assertThrows(IllegalArgumentException::class.java) {
            store.record(existing.item, PayloadExchange("changed".toByteArray(), null, null))
        }
        assertThrows(FileAlreadyExistsException::class.java) {
            store.record(existing.item, PayloadExchange(Base64.getDecoder().decode(existing.requestBase64), null, null))
        }
        val path = root.resolve("run/0.json")
        Files.writeString(path, Files.readString(path).replace(existing.requestBase64, Base64.getEncoder().encodeToString("changed".toByteArray())))
        assertThrows(IllegalArgumentException::class.java) { store.read(0) }
    }

    @Test fun `altered grep verdict is rejected without replaying the request`() {
        val directory = root.resolve("grep")
        val plan = plan()
        val store = PayloadEvidenceStore.create(directory, plan, listOf(ProfileGrep(mode = "replace", name = "probe", regex = "found")))
        val run = PayloadExecution(plan)
        var sends = 0
        run.execute({true}, { sends++; PayloadExchange(it, "found".toByteArray(), 200) }, store::record)
        val expected = run.snapshot().single()
        assertEquals("MATCH", store.read(0, expected).grep.single().state)
        val path = directory.resolve("0.json")
        val original = Files.readString(path)
        assertTrue(original.contains("\"state\":\"MATCH\""))
        Files.writeString(path, original.replace("\"state\":\"MATCH\"", "\"state\":\"NO_MATCH\""))
        assertThrows(IllegalArgumentException::class.java) { store.read(0, expected) }
        assertEquals(1, sends)
        Files.writeString(path, original)
        assertEquals("MATCH", store.read(0, expected).grep.single().state)
    }
}
