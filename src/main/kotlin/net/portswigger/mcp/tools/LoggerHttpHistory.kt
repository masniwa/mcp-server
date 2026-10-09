package net.portswigger.mcp.tools

// >> 20261009 mniwa Capture correlated cross-tool HTTP traffic without modifying messages or claiming native Logger UI history access.
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import kotlinx.serialization.Serializable
import net.portswigger.mcp.schema.HttpService
import java.time.Instant
import java.util.UUID
import java.util.regex.Pattern

@Serializable
data class LoggerHistoryItem(
    val id: Long,
    val captureId: String,
    val messageId: Int,
    val tool: String,
    val httpService: HttpService,
    val url: String,
    val request: String,
    val response: String?,
    val notes: String?,
    val requestTime: String?,
    val responseTime: String?,
    val requestObservation: String,
    val responseState: String
)

@Serializable
data class LoggerHistoryStatus(
    val captureId: String,
    val source: String,
    val captureStartedAt: String,
    val retainedEntries: Int,
    val firstRetainedId: Long?,
    val latestId: Long,
    val droppedEntries: Long,
    val captureErrors: Long,
    val maxEntries: Int,
    val maxBytes: Long,
    val retainedBytes: Long
)

class LoggerHttpHistory(
    private val maxEntries: Int = 5_000,
    private val maxBytes: Long = 64L * 1024 * 1024
) : HttpHandler {
    private val captureId = UUID.randomUUID().toString()
    private val startedAt = Instant.now().toString()
    private val items = linkedMapOf<Long, LoggerHistoryItem>()
    private val awaitingResponse = mutableMapOf<Int, Long>()
    private val sizes = mutableMapOf<Long, Long>()
    private var latestId = 0L
    private var bytes = 0L
    private var dropped = 0L
    private var errors = 0L

    init {
        require(maxEntries > 0 && maxBytes > 0)
    }

    override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent): RequestToBeSentAction {
        try {
            val service = requestToBeSent.httpService()
            recordRequest(requestToBeSent.messageId(), requestToBeSent.toolSource().toolType().name,
                HttpService(service.host(), service.port(), service.secure()), requestToBeSent.url(),
                requestToBeSent.toString(), requestToBeSent.annotations().notes())
        } catch (_: Exception) {
            recordError()
        }
        return RequestToBeSentAction.continueWith(requestToBeSent)
    }

    override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived): ResponseReceivedAction {
        try {
            val request = responseReceived.initiatingRequest()
            val service = request.httpService()
            recordResponse(responseReceived.messageId(), responseReceived.toolSource().toolType().name,
                HttpService(service.host(), service.port(), service.secure()), request.url(), request.toString(),
                responseReceived.toString(), responseReceived.annotations().notes())
        } catch (_: Exception) {
            recordError()
        }
        return ResponseReceivedAction.continueWith(responseReceived)
    }

    @Synchronized
    internal fun recordRequest(messageId: Int, tool: String, service: HttpService, url: String, request: String, notes: String?) {
        val id = ++latestId
        val item = LoggerHistoryItem(id, captureId, messageId, tool, service, url, request, null, notes,
            Instant.now().toString(), null, "REQUEST_HANDLER", "NO_RESPONSE_OBSERVED")
        awaitingResponse[messageId] = id
        retain(item)
    }

    @Synchronized
    internal fun recordResponse(messageId: Int, tool: String, service: HttpService, url: String,
                                request: String, response: String, notes: String?) {
        val id = awaitingResponse.remove(messageId)
        val existing = id?.let(items::get)
        val resolvedId = existing?.id ?: ++latestId
        retain(LoggerHistoryItem(resolvedId, captureId, messageId, existing?.tool ?: tool, service, url,
            request, response, notes ?: existing?.notes, existing?.requestTime, Instant.now().toString(),
            "RESPONSE_INITIATING_REQUEST", "RESPONSE_RECEIVED"))
    }

    private fun retain(item: LoggerHistoryItem) {
        val size = item.request.toByteArray(Charsets.UTF_8).size.toLong() +
            (item.response?.toByteArray(Charsets.UTF_8)?.size ?: 0) +
            (item.notes?.toByteArray(Charsets.UTF_8)?.size ?: 0) + 512L
        bytes -= sizes.remove(item.id) ?: 0
        items.remove(item.id)
        if (size > maxBytes) {
            awaitingResponse.entries.removeIf { it.value == item.id }
            dropped++
            return
        }
        items[item.id] = item
        sizes[item.id] = size
        bytes += size
        while (items.size > maxEntries || bytes > maxBytes) {
            val oldest = items.keys.minOrNull() ?: break
            items.remove(oldest)
            bytes -= sizes.remove(oldest) ?: 0
            awaitingResponse.entries.removeIf { it.value == oldest }
            dropped++
        }
    }

    @Synchronized
    private fun recordError() { errors++ }

    @Synchronized
    internal fun snapshot(regex: Pattern? = null): List<LoggerHistoryItem> = items.values.sortedBy { it.id }.filter {
        regex == null || regex.matcher(it.request).find() || regex.matcher(it.response.orEmpty()).find() ||
            regex.matcher(it.tool).find() || regex.matcher(it.url).find()
    }

    @Synchronized
    internal fun status(): LoggerHistoryStatus = LoggerHistoryStatus(captureId = captureId, source = "MCP_HTTP_HANDLER", captureStartedAt = startedAt,
        retainedEntries = items.size, firstRetainedId = items.keys.minOrNull(), latestId = latestId,
        droppedEntries = dropped, captureErrors = errors, maxEntries = maxEntries, maxBytes = maxBytes, retainedBytes = bytes)
}
// << mniwa
