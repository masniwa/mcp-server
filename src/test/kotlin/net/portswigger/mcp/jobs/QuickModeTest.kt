package net.portswigger.mcp.jobs

import io.mockk.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import net.portswigger.diagnosis.contract.*
import net.portswigger.diagnosis.runner.HumanApprover
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class QuickModeTest {
    @Test fun `operator selected Quick never calls a Swing stage approver`() {
        val delegate=object:HumanApprover {
            override fun review(plan:CompiledPlan,stage:ApprovalStage,report:ValidationReport?):String?=error("UI must not open")
        }
        val approver=ConfiguredJobApprover(delegate,true);val plan=mockk<CompiledPlan>()
        val record=ExecutionRecord("execution","digest","epoch",1)
        val report=ValidationReport("digest",emptyList(),1000,true,emptyList())
        assertTrue(approver.review(plan,ApprovalStage.PREPARATION,null)!!.startsWith("Quick:"))
        assertTrue(approver.review(plan,ApprovalStage.EXECUTION,report)!!.startsWith("Quick:"))
        assertTrue(approver.reviewRestore(plan,record,"cancelled")!!.startsWith("Quick:"))
        assertNull(approver.reviewColdCphRestore(plan,record,"stopped maintenance","snapshot-digest"))
        assertTrue(approver.reviewContinuation(plan,record,report)!!.startsWith("Quick:"))
    }
    @Test fun `review installation retains explicit operator decision`() {
        var count=0;val approver=ConfiguredJobApprover(HumanApprover { _,_,_ -> count++;null },false)
        assertNull(approver.review(mockk(),ApprovalStage.PREPARATION,null));assertEquals(1,count)
    }
    @Test fun `REVIEW maintenance decisions reach the human approver while Quick refuses them`() {
        val delegate=object:HumanApprover {
            override fun review(plan:CompiledPlan,stage:ApprovalStage,report:ValidationReport?)="human"
            override fun reviewCphPrune(names:List<String>,evidenceRef:String,currentDigest:String,targetDigest:String)="prune-operator"
            override fun reviewUnverifiedRestore(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String,currentDigest:String,coldCph:Boolean)="restore-operator"
            override fun reviewRestartCphRestore(sourceExecutionId:String,names:List<String>,evidenceRef:String,currentDigest:String,targetDigest:String)="restart-operator"
        }
        val review=ConfiguredJobApprover(delegate,false);val quick=ConfiguredJobApprover(delegate,true)
        val plan=mockk<CompiledPlan>();val record=ExecutionRecord("execution","digest","epoch",1)
        assertEquals("prune-operator",review.reviewCphPrune(listOf("job:demo:old"),"proof","before","after"))
        assertEquals("restore-operator",review.reviewUnverifiedRestore(plan,record,"proof","before",true))
        assertEquals("restart-operator",review.reviewRestartCphRestore("execution",listOf("job:old:a"),"proof","before","after"))
        assertNull(quick.reviewCphPrune(listOf("job:demo:old"),"proof","before","after"))
        assertNull(quick.reviewUnverifiedRestore(plan,record,"proof","before",true))
        assertNull(quick.reviewRestartCphRestore("execution",listOf("job:old:a"),"proof","before","after"))
    }
    @Test fun `Quick bypasses only diagnostic popups and keeps managed direct writes blocked`()=runBlocking {
        val config=McpConfig(mockk(relaxed=true),mockk(relaxed=true),true,true)
        val http=HttpRequestSecurity.approvalHandler;val data=DataAccessSecurity.approvalHandler
        val deniedHttp=mockk<UserApprovalHandler>();val deniedData=mockk<DataAccessApprovalHandler>()
        HttpRequestSecurity.approvalHandler=deniedHttp;DataAccessSecurity.approvalHandler=deniedData
        try {
            assertTrue(HttpRequestSecurity.checkHttpRequestPermission("fixture.invalid",8080,config))
            assertTrue(DataAccessSecurity.checkDataAccessPermission(DataAccessType.HTTP_HISTORY,config))
            assertTrue(DataAccessSecurity.checkDataAccessPermission(DataAccessType.LOGGER_HISTORY,config))
            coVerify(exactly=0) { deniedHttp.requestApproval(any(),any(),any(),any(),any()) }
            coVerify(exactly=0) { deniedData.requestDataAccess(any(),any()) }
            assertThrows(JobRejected::class.java) { ToolDispatch(true).publicCall("set_project_options",JsonObject(emptyMap())) }
            assertThrows(JobRejected::class.java) { ToolDispatch(true).publicCall("send_http1_request",JsonObject(emptyMap())) }
        } finally { HttpRequestSecurity.approvalHandler=http;DataAccessSecurity.approvalHandler=data }
    }
}
