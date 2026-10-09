package net.portswigger.mcp.security

// >> 20261009 mniwa Verify that Proxy history consent never silently grants access to cross-tool Logger capture.
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.*
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class LoggerAccessSecurityTest {
    @Test fun `logger access has independent approval and persisted grant`() = runBlocking {
        val values = mutableMapOf<String, Boolean>("requireDataAccessApproval" to true, "_alwaysAllowHttpHistory" to true)
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers { values[firstArg()] }
        every { storage.setBoolean(any(), any()) } answers { values[firstArg()] = secondArg(); Unit }
        every { storage.getString(any()) } returns ""
        val config = McpConfig(storage, mockk<Logging>(relaxed = true))
        val previous = DataAccessSecurity.approvalHandler
        val approval = mockk<DataAccessApprovalHandler>()
        coEvery { approval.requestDataAccess(DataAccessType.LOGGER_HISTORY, config) } returns false
        DataAccessSecurity.approvalHandler = approval
        try {
            assertTrue(DataAccessSecurity.checkDataAccessPermission(DataAccessType.HTTP_HISTORY, config))
            assertFalse(DataAccessSecurity.checkDataAccessPermission(DataAccessType.LOGGER_HISTORY, config))
            coVerify(exactly = 1) { approval.requestDataAccess(DataAccessType.LOGGER_HISTORY, config) }
            config.alwaysAllowLoggerHistory = true
            assertTrue(DataAccessSecurity.checkDataAccessPermission(DataAccessType.LOGGER_HISTORY, config))
            assertEquals(true, values["_alwaysAllowLoggerHistory"])
            coVerify(exactly = 1) { approval.requestDataAccess(DataAccessType.LOGGER_HISTORY, config) }
        } finally { DataAccessSecurity.approvalHandler = previous }
    }
}
// << mniwa
