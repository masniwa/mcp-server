package net.portswigger.mcp.tools

/** Cooperatively releases this callback's native wait after confirmed cancellation.
 * Never cancels an audit, retries a request, or interrupts a reused Scanner worker.
 * Unknown status and observation failures do not imply cancellation.
 */
internal class PayloadCancellationWatch(
    private val cancelled: () -> Boolean,
    private val intervalMillis: Long = 100
) {
    fun <T> during(action: () -> T): T {
        val owner = Thread.currentThread()
        val lock = Object()
        var active = true
        var interruptedByWatch = false
        val wasInterrupted = owner.isInterrupted
        val watcher = Thread({
            while (true) {
                synchronized(lock) {
                    if (!active) return@Thread
                    lock.wait(intervalMillis)
                    if (!active) return@Thread
                }
                val stop = try { cancelled() } catch (_: Exception) { false }
                if (stop) synchronized(lock) {
                    if (active) {
                        interruptedByWatch = true
                        owner.interrupt()
                    }
                    return@Thread
                }
            }
        }, "mcp-payload-cancellation").apply { isDaemon = true }
        watcher.start()
        try {
            return action()
        } finally {
            synchronized(lock) {
                active = false
                lock.notifyAll()
                // Do not leak our cancellation into the Scanner worker's next job.
                if (interruptedByWatch && !wasInterrupted) Thread.interrupted()
                if (wasInterrupted) owner.interrupt()
            }
        }
    }
}
