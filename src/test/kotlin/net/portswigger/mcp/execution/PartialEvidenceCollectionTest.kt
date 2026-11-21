package net.portswigger.mcp.execution

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class PartialEvidenceCollectionTest {
    @Test fun streamedPagesStayDurableAndCompletenessUsesOriginalLifecycleRatherThanReferences() {
        val directory=java.nio.file.Files.createTempDirectory("anonymous-evidence-")
        net.portswigger.diagnosis.runner.JobStore(directory).use { store ->
            val writer=net.portswigger.diagnosis.runner.EvidencePageWriter(store,"execution","audit")
            val result=collectPartialEvidence("audit",true,{ native() },{ emit -> emit(payload()) },{ status() },
                { _,emit -> emit(JsonPrimitive("{\"id\":1}")) },{ emit -> repeat(150) { emit(JsonPrimitive("issue-$it")) } },savePage=writer::save)
            assertEquals(JsonPrimitive(true),result["complete"])
            assertEquals(JsonPrimitive(true),result["quiescent"])
            assertEquals(150,result.getValue("siteMapIssues").jsonArray.size)
            assertFalse(result.toString().contains("issue-149"))
            val ref=result.getValue("siteMapIssues").jsonArray.last().jsonObject
            assertEquals(JsonPrimitive("issue-149"),net.portswigger.diagnosis.runner.SavedResults(store).resolvePage(ref))
            assertEquals(JsonPrimitive(false),result["diagnosisCompleted"])
        }
    }
    @Test fun pagePersistenceFailureDoesNotDiscardEarlierSourcesOrDeclareQuiescence() {
        val saved=mutableListOf<String>()
        val result=collectPartialEvidence("audit",true,{ native() },{ emit -> emit(payload()) },{ status() },
            { _,emit -> emit(JsonPrimitive("log")) },{ emit -> emit(JsonPrimitive("issue")) },savePage={ source,_ ->
                if(source=="loggerPages") throw net.portswigger.diagnosis.contract.JobRejected("STORE_SQLITE_FAILURE")
                saved.add(source);buildJsonObject { put("key",source) }
            })
        assertEquals(listOf("payloadPages","siteMapIssues"),saved)
        assertEquals(JsonPrimitive("STORE_SQLITE_FAILURE"),result.getValue("collectionErrors").jsonObject["loggerPages"])
        assertEquals(JsonPrimitive(false),result["quiescent"])
        assertEquals(JsonPrimitive(false),result["complete"])
    }
    @Test fun currentWindowCompletenessPreservesHistoricalErrorsButRejectsNewLoss() {
        fun metadata(errors:Int=4,id:Int=10)=buildJsonObject { put("captureId","capture");put("latestId",id);put("captureErrors",errors);put("droppedEntries",2) }
        val before=metadata()
        fun collect(after:JsonObject,checkpoint:JsonObject?=before)=collectPartialEvidence("audit",false,{ native() },{},
            { after },{ _,_ -> },{},checkpoint)
        val result=collect(metadata(id=12))
        assertEquals(JsonPrimitive(true),result["complete"])
        assertEquals(JsonPrimitive(4),result.getValue("loggerStatus").jsonObject["captureErrors"])
        assertEquals(JsonPrimitive(false),collect(metadata(errors=5,id=12))["complete"])
        assertEquals(JsonPrimitive(false),collect(metadata(id=9))["complete"])
        assertEquals(JsonPrimitive(false),collect(metadata(id=12),null)["complete"])
    }
    private fun native()=buildJsonObject { put("completed",true);put("auditRequestCount",7) }
    private fun status()=buildJsonObject { put("captureId","anonymous");put("droppedEntries",0);put("captureErrors",0) }
    private fun payload()=buildJsonObject { put("completed",true);put("payloadCallbackFinished",true);put("timingControlsFinished",true) }
    @Test fun independentFailuresRetainOtherEvidenceAndNeverProveCompletion() {
        for(failed in listOf("native","payload","loggerStatus","loggerPages","issues")) {
            val result=collectPartialEvidence("anonymous-audit",true,
                native={ if(failed=="native") error("native unavailable") else native() },
                payloadPages={ emit -> emit(payload());if(failed=="payload") error("second page unavailable") },
                loggerStatus={ if(failed=="loggerStatus") error("logger unavailable") else status() },
                loggerPages={ _,emit -> emit(JsonPrimitive("saved log"));if(failed=="loggerPages") error("later page unavailable") },
                issues={ emit -> emit(JsonPrimitive("saved issue"));if(failed=="issues") error("later page unavailable") })
            assertTrue(failed in result.getValue("collectionErrors").jsonObject)
            assertEquals(JsonPrimitive(false),result["complete"])
            assertEquals(JsonPrimitive(false),result["quiescent"])
            assertEquals(JsonPrimitive(false),result["diagnosisCompleted"])
            if(failed!="native") assertEquals(JsonPrimitive(7),result.getValue("native").jsonObject["auditRequestCount"])
            if(failed!="loggerStatus") assertEquals(1,result.getValue("loggerPages").jsonArray.size)
            assertEquals(1,result.getValue("payloadPages").jsonArray.size)
            assertEquals(1,result.getValue("siteMapIssues").jsonArray.size)
        }
    }
    @Test fun healthyCollectionStillRequiresExpectedPayloadAndQuiescentCallbacks() {
        fun collect(expected:Boolean,pages:Boolean)=collectPartialEvidence("anonymous-audit",expected,{ native() },
            { emit -> if(pages) emit(payload()) },{ status() },{ _,_ -> },{ _ -> })
        assertEquals(JsonPrimitive(true),collect(true,true)["complete"])
        assertEquals(JsonPrimitive(false),collect(true,false)["complete"])
        assertEquals(JsonPrimitive(true),collect(false,false)["complete"])
    }
}
