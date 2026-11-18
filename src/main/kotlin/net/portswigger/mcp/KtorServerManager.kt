package net.portswigger.mcp

import burp.api.montoya.MontoyaApi
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.mcp
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.tools.registerTools
// >> 20261009 mniwa Keep one cross-tool HTTP recorder across MCP server restarts and release it on extension shutdown.
import net.portswigger.mcp.tools.LoggerHttpHistory
// << mniwa
import java.net.URI
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import io.ktor.server.routing.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import net.portswigger.mcp.jobs.*
import net.portswigger.mcp.execution.*
import net.portswigger.mcp.tools.BurpExecutionContext
import net.portswigger.diagnosis.contract.*
import net.portswigger.diagnosis.runner.*
import java.nio.file.Path
import java.util.UUID
import java.nio.file.Files
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import io.ktor.utils.io.readRemaining
import kotlinx.io.readByteArray

class KtorServerManager(private val api: MontoyaApi, private val managed:ManagedSettings=ManagedSettings.forExtension()) : ServerManager {
    private val instanceId=UUID.randomUUID().toString()
    private val dispatch=ToolDispatch(managed.enabled)
    private val executionContext=BurpExecutionContext(api,CphClient(managed.cphToken,managed.connectionMetadata()))
    private var jobStore:JobStore?=null
    private var workerProtocol:WorkerProtocol?=null
    private var diagnosticJobs:DiagnosticJobService?=null

    // >> 20261009 mniwa Register HTTP observation once for this extension manager rather than once per MCP client or server start.
    // A managed job retains prerequisite/target/post traffic across every variant.
    // Keep the same byte bound and legacy capacity; never hide dropped evidence.
    private val loggerHistory = if (managed.enabled) LoggerHttpHistory(maxEntries = 20_000,
        archiveDirectory=managed.directory!!.resolve("http-capture")) else LoggerHttpHistory()
    private val loggerRegistration = api.http().registerHttpHandler(loggerHistory)
    // << mniwa

    private var server: EmbeddedServer<*, *>? = null
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()

    override fun start(config: McpConfig, callback: (ServerState) -> Unit) {
        callback(ServerState.Starting)

        executor.submit {
            try {
                server?.stop(1000, 5000)
                server = null

                val mcpServer = Server(
                    serverInfo = Implementation("burp-suite", "1.1.2"), options = ServerOptions(
                        capabilities = ServerCapabilities(
                            tools = ServerCapabilities.Tools(listChanged = false)
                        )
                    )
                )
                ToolDispatch.attach(mcpServer,dispatch)
                if(managed.enabled) requireJob(config.host in setOf("127.0.0.1","localhost"),"MANAGED_LOOPBACK_REQUIRED")
                if(managed.enabled && workerProtocol==null) {
                    val store=JobStore(managed.directory!!)
                    jobStore=store
                    val roots=managed.inputRoots
                    val generationsFile=managed.secretGenerationsFile
                    val port=MontoyaJobPort(api,dispatch,executionContext.cph,instanceId,managed.capabilities,store.directory,roots,
                        allowConfigurationEditing={config.configEditingTooling || managed.quick},secretGenerations={
                            generationsFile?.let { jobJson.decodeFromString<Map<String,String>>(Files.readString(it)) } ?: emptyMap()
                        },loggerHistory=loggerHistory)
                    val approver=ConfiguredJobApprover(SwingJobApprover(store.directory,
                        owner={ api.userInterface().swingUtils().suiteFrame() },phase={ diagnosticJobs?.approvalPhase(it) }),managed.quick)
                    val worker=GuardedWorker(port,store,approver)
                    workerProtocol=WorkerProtocol(worker)
                    val installation=managed.profileFile?.takeIf { !managed.quick }?.let { profile ->
                        InstallationVerification(port,store,approver,profile,{ name,request,sourcePort,response,trigger ->
                            val input=net.portswigger.mcp.tools.GenerateCphImportConfig(tabName=name,
                                modifyScopeExpression=trigger,matchExpression="{{setup_token}}",replacementExpression="\\g<token>",
                                issuerHost="127.0.0.1",issuerPort=sourcePort,singleRequest=request,singleResponse=response,
                                singleExtractExpression="(?P<token>[a-f0-9-]{36})",includeOptions=true)
                            val text=dispatch.workerCall("generate_cph_import_config",jobJson.encodeToJsonElement(input).jsonObject)
                                .joinToString("\n") { (it as io.modelcontextprotocol.kotlin.sdk.types.TextContent).text }
                            jobJson.parseToJsonElement(text).jsonObject
                        })
                    }
                    diagnosticJobs=DiagnosticJobService(worker,store,managed.quick,managed.profileFile,installation)
                }

                server = embeddedServer(Netty, port = config.port, host = config.host) {
                    install(CORS) {
                        allowHost("localhost:${config.port}")
                        allowHost("127.0.0.1:${config.port}")

                        allowMethod(HttpMethod.Get)
                        allowMethod(HttpMethod.Post)

                        allowHeader(HttpHeaders.ContentType)
                        allowHeader(HttpHeaders.Accept)
                        allowHeader("Last-Event-ID")

                        allowCredentials = false
                        allowNonSimpleContentTypes = true
                        maxAgeInSeconds = 3600
                    }

                    intercept(ApplicationCallPipeline.Call) {
                        val origin = call.request.header("Origin")
                        val host = call.request.header("Host")
                        val referer = call.request.header("Referer")
                        val userAgent = call.request.header("User-Agent")

                        if (origin != null && !isValidOrigin(origin)) {
                            api.logging().logToOutput("Blocked DNS rebinding attack from origin: $origin")
                            call.respond(HttpStatusCode.Forbidden)
                            return@intercept
                        } else if (isBrowserRequest(userAgent)) {
                            api.logging().logToOutput("Blocked browser request without Origin header")
                            call.respond(HttpStatusCode.Forbidden)
                            return@intercept
                        }

                        if (host != null && !isValidHost(host, config.port)) {
                            api.logging().logToOutput("Blocked DNS rebinding attack from host: $host")
                            call.respond(HttpStatusCode.Forbidden)
                            return@intercept
                        }

                        if (referer != null && !isValidReferer(referer)) {
                            api.logging().logToOutput("Blocked suspicious request from referer: $referer")
                            call.respond(HttpStatusCode.Forbidden)
                            return@intercept
                        }

                        call.response.header("X-Frame-Options", "DENY")
                        call.response.header("X-Content-Type-Options", "nosniff")
                        call.response.header("Referrer-Policy", "same-origin")
                        call.response.header("Content-Security-Policy", "default-src 'none'")
                    }

                    mcp {
                        mcpServer
                    }
                    routing {
                        post("/diagnosis/worker") {
                            if(!managed.authorized(call.request.header("Authorization"))) {
                                call.respond(HttpStatusCode.Forbidden);return@post
                            }
                            val maxBytes=16L*1024*1024
                            if((call.request.header(HttpHeaders.ContentLength)?.toLongOrNull() ?: 0)>maxBytes) {
                                call.respond(HttpStatusCode.PayloadTooLarge);return@post
                            }
                            val bytes=call.receiveChannel().readRemaining(maxBytes+1).readByteArray()
                            if(bytes.size>maxBytes) { call.respond(HttpStatusCode.PayloadTooLarge);return@post }
                            val payload=bytes.toString(Charsets.UTF_8)
                            val reply=try {
                                val request=jobJson.decodeFromString<WorkerRequest>(payload)
                                withContext(Dispatchers.IO) { workerProtocol!!.handle(request) }
                            } catch(e:Exception) { WorkerReply(false,errorCode="INVALID_WORKER_REQUEST") }
                            call.respondText(jobJson.encodeToString(reply),ContentType.Application.Json)
                        }
                    }

                    // >> 20261009 mniwa Share the live recorder with the read-only Logger history tools.
                    mcpServer.registerTools(api, config, loggerHistory,executionContext)
                    diagnosticJobs?.let { mcpServer.registerDiagnosticJobTool(it) }
                    // << mniwa
                }.apply {
                    start(wait = false)
                }

                api.logging().logToOutput("Started MCP server on ${config.host}:${config.port}")
                callback(ServerState.Running)

            } catch (e: Exception) {
                api.logging().logToError(e)
                callback(ServerState.Failed(e))
            }
        }
    }

    override fun stop(callback: (ServerState) -> Unit) {
        callback(ServerState.Stopping)

        executor.submit {
            try {
                server?.stop(1000, 5000)
                server = null
                api.logging().logToOutput("Stopped MCP server")
                callback(ServerState.Stopped)
            } catch (e: Exception) {
                api.logging().logToError(e)
                callback(ServerState.Failed(e))
            }
        }
    }

    override fun shutdown() {
        // >> 20261009 mniwa Stop retaining traffic when this extension manager is unloaded.
        loggerRegistration.deregister()
        // << mniwa
        server?.stop(1000, 5000)
        server = null
        diagnosticJobs?.close()
        diagnosticJobs=null
        loggerHistory.close()
        jobStore?.close()
        jobStore=null

        executor.shutdown()
        executor.awaitTermination(10, TimeUnit.SECONDS)
    }

    private fun isValidOrigin(origin: String): Boolean {
        try {
            val url = URI(origin).toURL()
            val hostname = url.host.lowercase()

            val allowedHosts = setOf("localhost", "127.0.0.1")

            return hostname in allowedHosts
        } catch (_: Exception) {
            return false
        }
    }

    private fun isBrowserRequest(userAgent: String?): Boolean {
        if (userAgent == null) return false

        val userAgentLower = userAgent.lowercase()
        val browserIndicators = listOf(
            "mozilla/", "chrome/", "safari/", "webkit/", "gecko/", "firefox/", "edge/", "opera/", "browser"
        )

        return browserIndicators.any { userAgentLower.contains(it) }
    }

    private fun isValidHost(host: String, expectedPort: Int): Boolean {
        try {
            val parts = host.split(":")
            val hostname = parts[0].lowercase()
            val port = if (parts.size > 1) parts[1].toIntOrNull() else null

            val allowedHosts = setOf("localhost", "127.0.0.1")
            if (hostname !in allowedHosts) {
                return false
            }

            if (port != null && port != expectedPort) {
                return false
            }

            return true
        } catch (_: Exception) {
            return false
        }
    }

    private fun isValidReferer(referer: String): Boolean {
        try {
            val url = URI(referer).toURL()
            val hostname = url.host.lowercase()

            val allowedHosts = setOf("localhost", "127.0.0.1")
            return hostname in allowedHosts

        } catch (_: Exception) {
            return false
        }
    }
}
