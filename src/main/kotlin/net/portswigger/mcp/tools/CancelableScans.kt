package net.portswigger.mcp.tools

import java.lang.management.ManagementFactory
import javax.management.InstanceNotFoundException
import javax.management.ObjectName
import kotlinx.serialization.json.*

/** Uses only public JMX/JDK values across Burp extension class loaders; no internal Burp reflection. */
internal class CancelableScans {
    fun call(arguments: Map<String, Any?>): JsonObject = try {
        val result = ManagementFactory.getPlatformMBeanServer().invoke(
            ObjectName("net.portswigger.mcp:type=LegacyScanBridge"), "execute",
            arrayOf(arguments), arrayOf("java.util.Map")
        )
        (jsonValue(result) as? JsonObject) ?: failure("INVALID_BRIDGE_RESPONSE")
    } catch (_: InstanceNotFoundException) {
        failure("BRIDGE_NOT_LOADED")
    } catch (_: Exception) {
        // Exceptions may contain raw requests or credentials: do not return them.
        failure("BRIDGE_CALL_FAILED")
    }

    private fun failure(code: String) = buildJsonObject {
        put("success", false); put("errorCode", code)
        put("message", "The optional cancelable-scan bridge is unavailable or the operation outcome is unknown. Read capabilities/status before retrying; never restart a scan with a new operationId to hide a timeout.")
    }

    private fun jsonValue(value: Any?): JsonElement = when (value) {
        null -> JsonNull
        is Boolean -> JsonPrimitive(value)
        is Number -> JsonPrimitive(value)
        is String -> JsonPrimitive(value)
        is Map<*, *> -> buildJsonObject { value.forEach { (key, item) -> require(key is String); put(key, jsonValue(item)) } }
        is Iterable<*> -> buildJsonArray { value.forEach { add(jsonValue(it)) } }
        else -> error("Unsupported bridge value")
    }
}

@kotlinx.serialization.Serializable
class GetCancelableScanCapabilities

@kotlinx.serialization.Serializable
data class GetCancelableActiveScanStatus(val bridgeId: String, val auditId: String? = null)

@kotlinx.serialization.Serializable
data class CancelActiveScan(val bridgeId: String, val auditId: String)
