package net.portswigger.mcp.tools

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

@Serializable
internal data class PayloadEvidenceRecord(
    val item: PayloadExecutionItem,
    val requestBase64: String,
    val responseBase64: String?,
    val grep: List<PayloadGrepObservation> = emptyList(),
    val submittedRequestBase64: String? = null
)

@Serializable
internal data class PayloadBaselineRecord(val requestBase64: String, val responseBase64: String?,
    val statusCode: Int?, val requestSha256: String, val responseSha256: String?)

/** Caller must choose a new run directory under the authorized evidence root.
 * Full wire evidence may contain credentials; never print it to normal progress logs.
 * Exclusive creation preserves history and detects duplicate writes. A partial file is an
 * explicit failed evidence commit, never a reason to replay the request.
 */
internal class PayloadEvidenceStore private constructor(private val directory: Path, private val grep: List<ProfileGrep>) {
    private val committedDigests = ConcurrentHashMap<Int, String>()
    private var baselineDigest: String? = null

    @Synchronized fun recordBaseline(exchange: PayloadExchange) {
        if (baselineDigest != null) return
        val record = PayloadBaselineRecord(Base64.getEncoder().encodeToString(exchange.request),
            exchange.response?.let { Base64.getEncoder().encodeToString(it) }, exchange.statusCode,
            sha256(exchange.request), exchange.response?.let(::sha256))
        val content = Json.encodeToString(record)
        Files.writeString(directory.resolve("baseline.json"), content, StandardOpenOption.CREATE_NEW)
        baselineDigest = sha256(content.toByteArray(Charsets.UTF_8))
    }

    @Synchronized fun readBaseline(): PayloadBaselineRecord? {
        val expected = baselineDigest ?: return null
        val bytes = Files.readAllBytes(directory.resolve("baseline.json"))
        require(sha256(bytes) == expected) { "Baseline differs from committed record" }
        return Json.decodeFromString<PayloadBaselineRecord>(bytes.toString(Charsets.UTF_8))
    }

    fun triage(item: PayloadExecutionItem, evidence: PayloadEvidenceRecord?): PayloadTriage =
        triagePayload(item, evidence, readBaseline(), grep)
    @Synchronized fun record(item: PayloadExecutionItem, exchange: PayloadExchange) {
        require(item.index >= 0) { "Negative evidence index" }
        require(item.requestSha256 == sha256(exchange.request)) { "Request evidence digest mismatch" }
        require(item.responseSha256 == exchange.response?.let(::sha256)) { "Response evidence digest mismatch" }
        require(item.statusCode == exchange.statusCode) { "Response status mismatch" }
        require(item.submittedRequestSha256 == exchange.submittedRequest?.let(::sha256)) { "Submitted request digest mismatch" }
        val content = Json.encodeToString(PayloadEvidenceRecord(item,
            Base64.getEncoder().encodeToString(exchange.request),
            exchange.response?.let { Base64.getEncoder().encodeToString(it) },
            observePayloadGrep(grep, item.mode, exchange.response),
            exchange.submittedRequest?.let { Base64.getEncoder().encodeToString(it) }))
        Files.writeString(directory.resolve("${item.index}.json"), content,
            StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
        committedDigests[item.index] = sha256(content.toByteArray(Charsets.UTF_8))
    }

    fun read(index: Int, expectedItem: PayloadExecutionItem? = null): PayloadEvidenceRecord {
        require(index >= 0) { "Negative evidence index" }
        val bytes = Files.readAllBytes(directory.resolve("$index.json"))
        require(committedDigests[index] == sha256(bytes)) { "Evidence differs from committed record" }
        val result = Json.decodeFromString<PayloadEvidenceRecord>(bytes.toString(Charsets.UTF_8))
        require(result.item.index == index) { "Evidence index mismatch" }
        require(expectedItem == null || result.item == expectedItem) { "Evidence differs from execution ledger" }
        require(sha256(Base64.getDecoder().decode(result.requestBase64)) == result.item.requestSha256) { "Corrupt request evidence" }
        require(result.responseBase64?.let { sha256(Base64.getDecoder().decode(it)) } == result.item.responseSha256) { "Corrupt response evidence" }
        require(result.submittedRequestBase64?.let { sha256(Base64.getDecoder().decode(it)) } == result.item.submittedRequestSha256) { "Corrupt submitted request evidence" }
        return result
    }

    companion object {
        fun createControls(directory: Path, rows: List<PayloadExecutionItem>, requestDigest: String): PayloadEvidenceStore {
            Files.createDirectory(directory)
            Files.writeString(directory.resolve("control-plan.json"), Json.encodeToString(rows), StandardOpenOption.CREATE_NEW)
            Files.writeString(directory.resolve("request.sha256"),requestDigest,StandardOpenOption.CREATE_NEW)
            return PayloadEvidenceStore(directory,emptyList())
        }
        fun create(directory: Path, plan: PayloadWirePlan, grep: List<ProfileGrep> = emptyList()): PayloadEvidenceStore {
            // Directory must not already exist, including a symlink. Parent provision is explicit.
            Files.createDirectory(directory)
            Files.writeString(directory.resolve("plan.json"), Json.encodeToString(plan.candidates), StandardOpenOption.CREATE_NEW)
            Files.writeString(directory.resolve("source.sha256"), plan.sourceSha256, StandardOpenOption.CREATE_NEW)
            Files.writeString(directory.resolve("request.sha256"), plan.requestSha256, StandardOpenOption.CREATE_NEW)
            Files.writeString(directory.resolve("grep.json"), Json.encodeToString(grep), StandardOpenOption.CREATE_NEW)
            return PayloadEvidenceStore(directory, grep.toList())
        }
    }
}
