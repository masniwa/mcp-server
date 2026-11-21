package net.portswigger.mcp.tools

import kotlinx.serialization.Serializable
import java.util.regex.Pattern

@Serializable
data class PayloadGrepObservation(val name: String, val mode: String, val state: String,
    val start: Int? = null, val end: Int? = null, val reason: String? = null)

/** Observations on UTF-8 decoded response text (including headers), not vulnerability verdicts.
 * Offsets are UTF-16 character offsets in that decoded text, not byte offsets.
 */
internal fun observePayloadGrep(definitions: List<ProfileGrep>, mode: String, response: ByteArray?,
    maxCharacterReads: Int = 2_000_000): List<PayloadGrepObservation> {
    require(maxCharacterReads >= 0)
    val text = response?.toString(Charsets.UTF_8)
    return definitions.filter { it.mode == mode }.map { definition ->
        if (text == null) PayloadGrepObservation(definition.name, mode, "NOT_EVALUATED", reason = "NO_RESPONSE")
        else try {
            val matcher = Pattern.compile(definition.regex).matcher(BoundedRegexText(text, RegexBudget(maxCharacterReads)))
            if (matcher.find()) PayloadGrepObservation(definition.name, mode, "MATCH", matcher.start(), matcher.end())
            else PayloadGrepObservation(definition.name, mode, "NO_MATCH")
        } catch (error: Exception) {
            PayloadGrepObservation(definition.name, mode, "ERROR", reason = error.javaClass.simpleName)
        } catch (_: StackOverflowError) {
            PayloadGrepObservation(definition.name, mode, "ERROR", reason = "REGEX_STACK_LIMIT")
        }
    }
}

private class RegexWorkLimit : RuntimeException()
private class RegexBudget(var remaining: Int) { fun consume() { if (remaining-- <= 0) throw RegexWorkLimit() } }
private class BoundedRegexText(private val text: CharSequence, private val budget: RegexBudget) : CharSequence {
    override val length: Int get() = text.length
    override fun get(index: Int): Char { budget.consume(); return text[index] }
    override fun subSequence(startIndex: Int, endIndex: Int): CharSequence = BoundedRegexText(text.subSequence(startIndex, endIndex), budget)
    override fun toString(): String = text.toString()
}
