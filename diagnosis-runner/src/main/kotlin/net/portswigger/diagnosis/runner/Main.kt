package net.portswigger.diagnosis.runner

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path

fun main(args:Array<String>) {
    require(args.size>=3) { "Usage: <prepare|run|start|poll|status|results|revoke> <executionId> <client-store> [job.json]; configure BURP_DIAG_WORKER_URL and BURP_DIAG_WORKER_TOKEN" }
    val url=URI(System.getenv("BURP_DIAG_WORKER_URL") ?: "http://127.0.0.1:9876/diagnosis/worker")
    val token=System.getenv("BURP_DIAG_WORKER_TOKEN") ?: error("Worker token is required; never pass it on the command line")
    JobStore(Path.of(args[2])).use { store ->
        val runner=JobRunner(HttpWorkerConnection(url,token),store)
        val result=when(args[0]) {
            "prepare" -> runner.prepare(args[1],jobJson.decodeFromString<JobProposal>(Files.readString(Path.of(args[3]))))
            "start" -> runner.start(args[1])
            "run" -> jobJson.encodeToJsonElement(runner.run(args[1]))
            "reconcile" -> runner.call("reconcile",args[1],buildJsonObject { put("evidenceRef",args[3]) })
            "poll","status","results","refresh_results","revoke","renew_continuation" -> runner.call(args[0],args[1])
            else -> error("Unsupported command")
        }
        val path=store.directory.resolve("last-result.json")
        Files.writeString(path,result.toString())
        // Results/probes may contain credentials. Display only their protected local location.
        println("Operation recorded: $path")
    }
}
