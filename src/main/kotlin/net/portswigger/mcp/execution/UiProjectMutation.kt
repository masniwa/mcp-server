package net.portswigger.mcp.execution

import kotlinx.serialization.json.JsonObject
import net.portswigger.diagnosis.contract.*
import net.portswigger.diagnosis.runner.projectNativeScopeEquivalent
import java.util.concurrent.FutureTask
import javax.swing.SwingUtilities

/** Serialize human UI edits with compare/import/readback. Never hold EDT across CPH HTTP calls. */
internal class UiProjectMutation(
    private val read:()->JsonObject,
    private val importPatch:(JsonObject)->Unit
) {
    fun apply(expected:JsonObject,target:JsonObject):JsonObject {
        val patch=recoveryProjectPatch(expected,target)
        val task=FutureTask<JsonObject> {
            requireJob(canonical(read())==canonical(expected),"PROJECT_CHANGED_BEFORE_IMPORT")
            if(patch.isNotEmpty()) importPatch(patch)
            val observed=read()
            requireJob(projectNativeScopeEquivalent(target,observed),"PROJECT_IMPORT_READBACK_CHANGED")
            observed
        }
        if(SwingUtilities.isEventDispatchThread()) task.run() else SwingUtilities.invokeAndWait(task)
        return try { task.get() } catch(error:java.util.concurrent.ExecutionException) {
            throw (error.cause as? Exception ?: error)
        }
    }
}