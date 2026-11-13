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
    val responseState: String,
    val sendCompletionState: String? = null,
    val sendCompletionTime: String? = null
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
    val retainedBytes: Long,
    val storageMode:String="MEMORY",val memoryEntries:Int=0,val memoryBytes:Long=0,val memoryEvictedEntries:Long=0
)

class LoggerHttpHistory(
    private val maxEntries: Int = 5_000,
    private val maxBytes: Long = 64L * 1024 * 1024,
    archiveDirectory:java.nio.file.Path?=null
) : HttpHandler, AutoCloseable {
    private val captureId = UUID.randomUUID().toString()
    private val startedAt = Instant.now().toString()
    private val items = linkedMapOf<Long, LoggerHistoryItem>()
    private val awaitingResponse = mutableMapOf<Int, Long>()
    private val sizes = mutableMapOf<Long, Long>()
    private var latestId = 0L
    private var bytes = 0L
    private var dropped = 0L
    private var errors = 0L
    private val archive=archiveDirectory?.let { LoggerArchive(it,captureId) }
    private var memoryEvicted=0L
    internal class SendObservation internal constructor(
        val afterId:Long,val service:HttpService,val request:String,val errors:Long,val dropped:Long
    )
    private val activeSends=mutableSetOf<SendObservation>()

    /** The synchronous send lifetime is independent of whether a response handler fires. */
    @Synchronized internal fun beginSend(service:HttpService,request:String):SendObservation =
        SendObservation(latestId,service,request,errors,dropped).also { activeSends.add(it) }

    @Synchronized internal fun endSend(observation:SendObservation,returnedService:HttpService?,returnedRequest:String?) {
        if(observation !in activeSends) return
        try {
            // No URL-only, last-row or time-based inference. Multiple messages (including
            // Macro traffic), modifications, missing evidence and exceptional returns stay unresolved.
            if(returnedService!=observation.service || returnedRequest!=observation.request ||
                errors!=observation.errors || dropped!=observation.dropped) return
            val window=page(2,0,observation.afterId,latestId)
            val item=window.singleOrNull() ?: return
            if(item.tool!="EXTENSIONS" || item.httpService!=returnedService || item.request!=returnedRequest) return
            retain(item.copy(sendCompletionState="SEND_RETURNED",sendCompletionTime=Instant.now().toString()))
        } catch(_:Exception) { errors++ }
        finally { activeSends.remove(observation) }
    }

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
        val id = awaitingResponse.remove(messageId) ?: archive?.pendingId(messageId)
        val existing = id?.let { items[it] ?: archive?.byId(it) }
        val resolvedId = existing?.id ?: ++latestId
        retain(LoggerHistoryItem(resolvedId, captureId, messageId, existing?.tool ?: tool, service, url,
            request, response, notes ?: existing?.notes, existing?.requestTime, Instant.now().toString(),
            "RESPONSE_INITIATING_REQUEST", "RESPONSE_RECEIVED",existing?.sendCompletionState,existing?.sendCompletionTime))
    }

    private fun retain(item: LoggerHistoryItem) {
        val size = item.request.toByteArray(Charsets.UTF_8).size.toLong() +
            (item.response?.toByteArray(Charsets.UTF_8)?.size ?: 0) +
            (item.notes?.toByteArray(Charsets.UTF_8)?.size ?: 0) + 512L
        val committed=if(archive==null) false else try { archive.put(item,size);true } catch(_:Exception) { errors++;false }
        bytes -= sizes.remove(item.id) ?: 0
        items.remove(item.id)
        if (size > maxBytes) {
            awaitingResponse.entries.removeIf { it.value == item.id }
            if(committed) memoryEvicted++ else dropped++
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
            if(committed) memoryEvicted++ else dropped++
        }
    }

    @Synchronized
    private fun recordError() { errors++ }

    // >> 20261014 mniwa Resolve retained identifiers atomically and reject unsupported native UI or stale capture lookups.
    @Synchronized
    internal fun lookup(requestId: Long, idType: LoggerRequestIdType, expectedCaptureId: String?): RequestIdLookupResult {
        require(requestId >= 0) { "requestId must be non-negative" }
        if (expectedCaptureId != null && expectedCaptureId != captureId) return RequestIdLookupResult("CAPTURE_MISMATCH", idType.name, requestId, captureId, capture = status())
        if (idType == LoggerRequestIdType.LOGGER_UI) return RequestIdLookupResult("UNSUPPORTED_UI_ID", idType.name, requestId, captureId, capture = status())
        require(!expectedCaptureId.isNullOrBlank()) { "captureId is required for captured Logger identifiers" }
        require(idType != LoggerRequestIdType.HTTP_MESSAGE_ID || requestId <= Int.MAX_VALUE) { "HTTP_MESSAGE_ID must fit a signed 32-bit integer" }
        val matches = when (idType) {
            LoggerRequestIdType.MCP_CAPTURE_ID -> listOfNotNull(archive?.byId(requestId) ?: items[requestId])
            LoggerRequestIdType.HTTP_MESSAGE_ID -> archive?.byMessage(requestId.toInt()) ?: items.values.filter { it.messageId.toLong() == requestId }
            LoggerRequestIdType.LOGGER_UI -> emptyList()
        }
        return RequestIdLookupResult(when (matches.size) { 0 -> "NOT_RETAINED_OR_NOT_CAPTURED"; 1 -> "FOUND"; else -> "AMBIGUOUS" },
            idType.name, requestId, captureId, logger = matches.singleOrNull(), capture = status())
    }
    // << mniwa

    internal fun snapshot(regex: Pattern? = null): List<LoggerHistoryItem> {
        if(archive!=null) return page(Int.MAX_VALUE,0,regex=regex)
        val entries = synchronized(this) { items.values.toList() }.sortedBy { it.id }
        val search = regex?.let { HistoryRegex(it) } ?: return entries
        return entries.filter {
            search.contains(it.request) || search.contains(it.response.orEmpty()) ||
                search.contains(it.tool) || search.contains(it.url)
        }
    }

    @Synchronized internal fun page(count:Int,offset:Int,afterId:Long=0,throughId:Long=latestId,regex:Pattern?=null):List<LoggerHistoryItem> {
        require(count>0 && offset>=0 && afterId>=0 && throughId>=afterId)
        if(archive!=null) return archive.page(count,offset,afterId,throughId,regex)
        val entries=items.values.filter { it.id>afterId && it.id<=throughId }.sortedBy { it.id }
        val search=regex?.let(::HistoryRegex)
        return (if(search==null) entries else entries.filter {
            search.contains(it.request) || search.contains(it.response.orEmpty()) || search.contains(it.tool) || search.contains(it.url)
        }).drop(offset).take(count)
    }

    @Synchronized internal fun quiescent(services:Set<HttpService>):Boolean {
        if(errors>0 || dropped>0 || activeSends.any { send -> services.any {
            it.host.equals(send.service.host,true) && it.port==send.service.port && it.secure==send.service.secure
        } }) return false
        return archive?.quiescent(services) ?: awaitingResponse.values.none { id ->
            items[id]?.let { it.httpService in services && it.tool in setOf("SCANNER","EXTENSIONS") && it.sendCompletionState!="SEND_RETURNED" } ?: true
        }
    }

    @Synchronized
    internal fun status(): LoggerHistoryStatus {
        val disk=try { archive?.stats() } catch(_:Exception) { errors++;null }
        return LoggerHistoryStatus(captureId = captureId, source = "MCP_HTTP_HANDLER", captureStartedAt = startedAt,
            retainedEntries = disk?.first ?: items.size, firstRetainedId = disk?.second ?: items.keys.minOrNull(), latestId = latestId,
            droppedEntries = dropped, captureErrors = errors, maxEntries = maxEntries, maxBytes = maxBytes, retainedBytes = disk?.third ?: bytes,
            storageMode=if(archive==null) "MEMORY" else if(disk==null) "DISK_ERROR" else "DISK",memoryEntries=items.size,memoryBytes=bytes,memoryEvictedEntries=memoryEvicted)
    }
    @Synchronized override fun close() { archive?.close() }
}
// << mniwa

// >> 20261014 mniwa Return full request pairs with explicit identifier namespaces and non-success lookup states.
@Serializable
enum class LoggerRequestIdType { LOGGER_UI, MCP_CAPTURE_ID, HTTP_MESSAGE_ID }

@Serializable
data class ProxyRequestIdItem(val requestId: Int, val httpService: HttpService, val url: String,
    val request: String, val response: String?, val notes: String?, val time: String, val responseState: String,
    val requestBase64:String?=null,val responseBase64:String?=null,val parameters:List<NativeParameterMetadata>?=null)

@Serializable
data class RequestIdLookupResult(val status: String, val idType: String, val requestId: Long,
    val captureId: String, val proxy: ProxyRequestIdItem? = null, val logger: LoggerHistoryItem? = null,
    val capture: LoggerHistoryStatus? = null)
// << mniwa
