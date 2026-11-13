package net.portswigger.mcp.tools

import java.util.regex.Pattern

/** One budget spans all fields and entries of a search. Exhaustion is never a negative match. */
internal class HistoryRegex(private val pattern: Pattern, private val maxReads: Long = 20_000_000) {
    private var remaining = maxReads
    init { require(maxReads >= 0) }

    fun contains(text: String): Boolean = try {
        pattern.matcher(Text(text)).find()
    } catch (error: StackOverflowError) {
        throw IllegalArgumentException("REGEX_STACK_LIMIT: history search incomplete; simplify the regex", error)
    }

    private inner class Text(private val value: CharSequence) : CharSequence {
        override val length: Int get() = value.length
        override fun get(index: Int): Char {
            check(!Thread.currentThread().isInterrupted) { "REGEX_INTERRUPTED: history search incomplete" }
            check(remaining-- > 0) {
                "REGEX_WORK_LIMIT: history search incomplete after $maxReads character reads; use a simpler or anchored regex, or read history pages"
            }
            return value[index]
        }
        override fun subSequence(startIndex: Int, endIndex: Int): CharSequence = Text(value.subSequence(startIndex, endIndex))
        override fun toString(): String = value.toString()
    }
}
