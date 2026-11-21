package net.portswigger.diagnosis.runner

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import java.sql.DriverManager

class EvidencePagesTest {
    @Test fun metadataOnlyVerificationStreamsChunksAndRejectsChangedMissingOrNonStringPages() {
        val page=JsonPrimitive("日本🍍\n\"anonymous\"".repeat(100000))
        JobStore(directory).use { store ->
            val reference=EvidencePageWriter(store,"execution","audit").save("siteMapIssues",page).jsonObject
            val key=reference.getValue("key").jsonPrimitive.content
            val digest=reference.getValue("digest").jsonPrimitive.content
            val metadata=store.verifyJsonString(key,digest)
            assertEquals(JsonPrimitive(true),metadata["verified"])
            assertEquals(page.toString().toByteArray().size.toLong(),metadata.getValue("storedJsonUtf8Bytes").jsonPrimitive.long)
            assertEquals("EVIDENCE_CHANGED",assertThrows(JobRejected::class.java) { store.verifyJsonString(key,"wrong") }.code)
            store.put("object",buildJsonObject { put("value","not a string page") })
            assertEquals("EVIDENCE_STRING_PAGE_REQUIRED",assertThrows(JobRejected::class.java) { store.verifyJsonString("object",fingerprint(store.get("object")!!)) }.code)
            DriverManager.getConnection("jdbc:sqlite:"+directory.resolve("jobs.sqlite")).use { db ->
                db.prepareStatement("DELETE FROM json_chunks WHERE namespace='record' AND owner=? AND part=1").use { it.setString(1,key);it.executeUpdate() }
            }
            assertEquals("CORRUPT_JSON_CHUNKS",assertThrows(JobRejected::class.java) { store.verifyJsonString(key,digest) }.code)
        }
    }
    @TempDir lateinit var directory:Path
    @Test fun pagesSurviveInterruptionAndRestartWithoutAggregatingOrInventingCompletion() {
        val body=JsonPrimitive("anonymous-response".repeat(100000))
        var reference:JsonElement?=null
        JobStore(directory).use { store ->
            store.put("execution:execution",buildJsonObject { put("state","RECOVERY_REQUIRED") })
            reference=EvidencePageWriter(store,"execution","audit").save("siteMapIssues",body)
            val saved=SavedResults(store).read("execution")
            assertTrue(saved.getValue("records").jsonArray.isEmpty())
            assertEquals(JsonPrimitive("COLLECTING"),saved.getValue("collections").jsonArray.single().jsonObject["state"])
            assertEquals(JsonPrimitive(false),saved["diagnosisCompleted"])
        }
        JobStore(directory).use { store ->
            assertEquals(body,SavedResults(store).resolvePage(reference!!.jsonObject))
            val writer=EvidencePageWriter(store,"execution","audit")
            assertEquals(reference,writer.save("siteMapIssues",body))
            writer.finish(buildJsonObject { put("native","AUDIT_STATUS_MISSING") })
            assertEquals(1,store.keys("evidence-page:").size)
            val states=SavedResults(store).read("execution").getValue("collections").jsonArray.map { it.jsonObject["state"] }
            assertTrue(JsonPrimitive("PARTIAL") in states)
        }
    }
    @Test fun referencesAreLazyDigestVerifiedAndLegacyObjectsStayInline() {
        JobStore(directory).use { store ->
            val writer=EvidencePageWriter(store,"execution","audit")
            val first=writer.save("siteMapIssues",JsonPrimitive("large first issue"))
            val second=writer.save("siteMapIssues",JsonPrimitive("second issue"))
            val record=buildJsonObject { put("evidencePageFormat",EVIDENCE_PAGE_FORMAT);put("siteMapIssues",JsonArray(listOf(first,second))) }
            store.put(first.jsonObject.getValue("key").jsonPrimitive.content,JsonPrimitive("corrupted"))
            val saved=SavedResults(store)
            assertEquals(listOf(JsonPrimitive("second issue")),saved.pages(record,"siteMapIssues",1).toList())
            assertEquals("EVIDENCE_CHANGED",assertThrows(JobRejected::class.java) { saved.pages(record,"siteMapIssues").first() }.code)
            val legacy=buildJsonObject { put("siteMapIssues",JsonArray(listOf(first))) }
            assertEquals(listOf(first),saved.pages(legacy,"siteMapIssues").toList())
        }
    }
    @Test fun failedPageTransactionRetainsEarlierProgressAndDoesNotPublishItsReference() {
        JobStore(directory).use { store ->
            store.put("execution:execution",JsonObject(emptyMap()))
            val writer=EvidencePageWriter(store,"execution","audit")
            val first=writer.save("siteMapIssues",JsonPrimitive("first"))
            DriverManager.getConnection("jdbc:sqlite:"+directory.resolve("jobs.sqlite")).use { db ->
                db.createStatement().use { it.execute("CREATE TRIGGER fail_page BEFORE INSERT ON records WHEN NEW.key LIKE 'evidence-page:%' BEGIN SELECT RAISE(ABORT,'private'); END") }
            }
            assertThrows(JobRejected::class.java) { writer.save("siteMapIssues",JsonPrimitive("second")) }
            val progress=SavedResults(store).read("execution").getValue("collections").jsonArray.single().jsonObject
            assertEquals(JsonArray(listOf(first)),progress["siteMapIssues"])
        }
    }
}
