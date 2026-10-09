package net.portswigger.mcp.security

import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.config.McpConfig
import javax.swing.SwingUtilities
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

enum class DataAccessType() {
    // >> 20261009 mniwa Require separate consent for cross-tool Logger capture rather than widening Proxy history permission.
    HTTP_HISTORY(), WEBSOCKET_HISTORY(), ORGANIZER(), LOGGER_HISTORY();
    // << mniwa
}

interface DataAccessApprovalHandler {
    suspend fun requestDataAccess(accessType: DataAccessType, config: McpConfig): Boolean
}

class SwingDataAccessApprovalHandler : DataAccessApprovalHandler {
    override suspend fun requestDataAccess(
        accessType: DataAccessType, config: McpConfig
    ): Boolean {
        return suspendCoroutine { continuation ->
            SwingUtilities.invokeLater {
                val accessTypeName = when (accessType) {
                    DataAccessType.HTTP_HISTORY -> "HTTP history"
                    DataAccessType.WEBSOCKET_HISTORY -> "WebSocket history"
                    DataAccessType.ORGANIZER -> "Organizer items"
                    // >> 20261009 mniwa Identify the broader cross-tool HTTP capture in the approval dialog.
                    DataAccessType.LOGGER_HISTORY -> "MCP Logger HTTP capture (all tools)"
                    // << mniwa
                }

                val message = buildString {
                    appendLine("An MCP client is requesting access to your Burp Suite $accessTypeName.")
                    appendLine()
                    appendLine("This may include sensitive data from previous web sessions.")
                    appendLine("Choose how you would like to respond:")
                }

                val options = arrayOf(
                    "Allow Once", "Always Allow $accessTypeName", "Deny"
                )

                val burpFrame = findBurpFrame()

                val result = Dialogs.showOptionDialog(
                    burpFrame, message, options
                )

                when (result) {
                    0 -> {
                        continuation.resume(true)
                    }

                    1 -> {
                        when (accessType) {
                            DataAccessType.HTTP_HISTORY -> config.alwaysAllowHttpHistory = true
                            DataAccessType.WEBSOCKET_HISTORY -> config.alwaysAllowWebSocketHistory = true
                            DataAccessType.ORGANIZER -> config.alwaysAllowOrganizer = true
                            // >> 20261009 mniwa Persist only the independently granted Logger access permission.
                            DataAccessType.LOGGER_HISTORY -> config.alwaysAllowLoggerHistory = true
                            // << mniwa
                        }
                        continuation.resume(true)
                    }

                    else -> {
                        continuation.resume(false)
                    }
                }
            }
        }
    }
}

object DataAccessSecurity {

    var approvalHandler: DataAccessApprovalHandler = SwingDataAccessApprovalHandler()

    suspend fun checkDataAccessPermission(
        accessType: DataAccessType, config: McpConfig
    ): Boolean {
        if (!config.requireDataAccessApproval) {
            return true
        }

        val isAlwaysAllowed = when (accessType) {
            DataAccessType.HTTP_HISTORY -> config.alwaysAllowHttpHistory
            DataAccessType.WEBSOCKET_HISTORY -> config.alwaysAllowWebSocketHistory
            DataAccessType.ORGANIZER -> config.alwaysAllowOrganizer
            // >> 20261009 mniwa Do not reuse an existing Proxy history grant for Logger traffic.
            DataAccessType.LOGGER_HISTORY -> config.alwaysAllowLoggerHistory
            // << mniwa
        }

        if (isAlwaysAllowed) {
            return true
        }

        return approvalHandler.requestDataAccess(accessType, config)
    }
}
