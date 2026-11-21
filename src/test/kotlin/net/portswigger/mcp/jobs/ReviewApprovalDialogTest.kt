package net.portswigger.mcp.jobs

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import net.portswigger.diagnosis.contract.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.awt.Component
import java.awt.Container
import java.awt.Dimension
import java.awt.Font
import java.awt.Insets
import java.awt.Rectangle
import java.awt.event.ActionEvent
import java.awt.event.KeyEvent
import java.util.concurrent.FutureTask
import javax.swing.*

class ReviewApprovalDialogTest {
    private fun <T> onEdt(block:()->T):T {
        val task=FutureTask(block)
        SwingUtilities.invokeAndWait(task)
        return task.get()
    }

    private fun layoutTree(component:Component) {
        if(component is Container) {
            component.doLayout()
            component.components.forEach { layoutTree(it) }
        }
    }

    private fun setFontTree(component:Component,size:Int) {
        component.font=Font(Font.DIALOG,Font.PLAIN,size)
        if(component is Container) component.components.forEach { setFontTree(it,size) }
    }

    private fun press(root:JRootPane,key:Int) {
        val name=root.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).get(KeyStroke.getKeyStroke(key,0))
        root.actionMap.get(name).actionPerformed(ActionEvent(root,ActionEvent.ACTION_PERFORMED,"test key"))
    }

    private fun root(panel:ReviewApprovalPanel,width:Int=640,height:Int=360)=JRootPane().apply {
        contentPane=panel
        panel.installKeys(this)
        setSize(width,height)
        layoutTree(this)
    }

    @Test fun `long review content scrolls while all human controls fit small and large font layouts`()=onEdt {
        val longText=("対象・設定・実通信の証拠を確認してください。 "+"long-path/".repeat(100)+"\n").repeat(150)
        for((width,height,font) in listOf(Triple(480,320,28),Triple(640,360,36),Triple(800,600,48))) {
            for(tabbed in listOf(false,true)) {
                val pages=listOf(ApprovalPage("対象範囲と証拠",longText))+
                    if(tabbed) listOf(ApprovalPage("Burp設定（保護対象の値はハッシュ表示）",longText,false)) else emptyList()
                val panel=ReviewApprovalPanel(pages,"承認段階：実行。86400秒間の許可。 "+"説明文。".repeat(100)) {}
                setFontTree(panel,font)
                root(panel,width,height)
                val visible=Rectangle(0,0,panel.width,panel.height)
                for(control in listOf(panel.footer,panel.confirmation,panel.approve,panel.cancel)) {
                    val bounds=SwingUtilities.convertRectangle(control.parent,control.bounds,panel)
                    assertTrue(visible.contains(bounds),"${width}x$height, font=$font, tabbed=$tabbed: ${control.javaClass.simpleName} $bounds outside $visible")
                    assertTrue(bounds.width>0 && bounds.height>0)
                }
                for(control in listOf(panel.confirmation,panel.approve,panel.cancel)) {
                    assertTrue(control.width>=control.preferredSize.width,"${control.javaClass.simpleName} label clipped at $width, font=$font")
                    assertTrue(control.height>=control.preferredSize.height)
                }
                val body=panel.components.single { it!==panel.footer }
                assertTrue(body.height>0,"Review body must remain available")
                assertTrue(body.y+body.height<=panel.footer.y)
                val scroll=if(body is JScrollPane) body else (body as JTabbedPane).getComponentAt(0) as JScrollPane
                assertTrue(scroll.viewport.extentSize.height>0)
                assertTrue(scroll.verticalScrollBar.maximum>scroll.verticalScrollBar.visibleAmount,"Long text must remain scrollable")
                val area=scroll.viewport.view as JTextArea
                assertTrue(area.text.contains("実行。86400秒間"),"Stage and duration must remain in the review body")
                assertTrue(area.text.endsWith(longText),"All review text must remain available")
            }
        }
    }

    @Test fun `OK and Enter require a checked confirmation and the action handler rechecks it`()=onEdt {
        val decisions=mutableListOf<Boolean>()
        val panel=ReviewApprovalPanel(listOf(ApprovalPage("操作","content")),"explanation",decisions::add)
        val root=root(panel)
        assertFalse(panel.approve.isEnabled)
        assertNull(root.defaultButton)
        val enterName=root.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).get(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER,0))
        assertFalse(root.actionMap.get(enterName).isEnabled)
        press(root,KeyEvent.VK_ENTER)
        panel.approve.actionListeners.forEach { it.actionPerformed(ActionEvent(panel.approve,ActionEvent.ACTION_PERFORMED,"direct event")) }
        assertNull(panel.decision)
        assertTrue(decisions.isEmpty())
        panel.confirmation.isSelected=true
        assertTrue(panel.approve.isEnabled)
        assertSame(panel.approve,root.defaultButton)
        assertTrue(root.actionMap.get(enterName).isEnabled)
        panel.confirmation.isSelected=false
        assertFalse(panel.approve.isEnabled)
        assertNull(root.defaultButton)
        press(root,KeyEvent.VK_ENTER)
        assertNull(panel.decision)
        panel.confirmation.isSelected=true
        press(root,KeyEvent.VK_ENTER)
        assertEquals(true,panel.decision)
        assertEquals(listOf(true),decisions)
        panel.cancel.doClick(0)
        assertEquals(listOf(true),decisions,"A completed decision cannot be replaced")
    }

    @Test fun `checking alone never approves and checked OK records one human decision`()=onEdt {
        val decisions=mutableListOf<Boolean>()
        val panel=ReviewApprovalPanel(listOf(ApprovalPage("操作","content")),"explanation",decisions::add)
        root(panel)
        panel.confirmation.doClick(0)
        assertNull(panel.decision)
        assertTrue(decisions.isEmpty())
        panel.approve.doClick(0)
        assertEquals(true,panel.decision)
        assertEquals(listOf(true),decisions)
    }

    @Test fun `Cancel Escape and the window close rejection path deny with either checkbox state`()=onEdt {
        for(checked in listOf(false,true)) {
            for(method in listOf("Cancel","CancelEnter","Escape","WindowClose")) {
                val decisions=mutableListOf<Boolean>()
                val panel=ReviewApprovalPanel(listOf(ApprovalPage("操作","content")),"explanation",decisions::add)
                val root=root(panel)
                panel.confirmation.isSelected=checked
                when(method) {
                    "Cancel" -> panel.cancel.doClick(0)
                    "CancelEnter" -> {
                        val action=panel.cancel.getInputMap(JComponent.WHEN_FOCUSED).get(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER,0))
                        panel.cancel.actionMap.get(action).actionPerformed(ActionEvent(panel.cancel,ActionEvent.ACTION_PERFORMED,"focused Enter"))
                    }
                    "Escape" -> press(root,KeyEvent.VK_ESCAPE)
                    else -> panel.reject() // The dialog windowClosing listener uses the same rejection path.
                }
                assertEquals(false,panel.decision,"$method checked=$checked")
                panel.confirmation.isSelected=true
                panel.approve.doClick(0)
                assertEquals(listOf(false),decisions,"A denial cannot be replaced by a later event")
            }
        }
    }

    @Test fun `dialog bounds respect negative monitor coordinates and every taskbar inset`() {
        val area=ApprovalDialogBounds.usable(Rectangle(-1600,-900,1600,900),Insets(24,10,48,36))
        assertEquals(Rectangle(-1590,-876,1554,828),area)
        val initial=ApprovalDialogBounds.initial(Dimension(4000,4000),Dimension(400,180),area,Rectangle(-1500,-800,1000,700))
        assertTrue(area.contains(initial))
        assertEquals(1000,initial.width)
        assertEquals(760,initial.height)
        assertEquals(area,ApprovalDialogBounds.fit(Rectangle(100,100,5000,5000),area))
        val resized=ApprovalDialogBounds.fit(Rectangle(500,-3000,800,500),area)
        assertTrue(area.contains(resized))
        assertEquals(area.x+area.width-800,resized.x)
        assertEquals(area.y,resized.y)
        val otherMonitor=ApprovalDialogBounds.usable(Rectangle(1920,0,1280,1024),Insets(0,0,40,0))
        val resizedOnOtherMonitor=ApprovalDialogBounds.fit(Rectangle(2000,100,1400,1000),otherMonitor)
        assertTrue(otherMonitor.contains(resizedOnOtherMonitor))
        assertEquals(otherMonitor.width,resizedOnOtherMonitor.width)
        assertTrue(resizedOnOtherMonitor.x>0,"Resizing on another monitor must use that monitor's work area")
    }

    @Test fun `initial and resized bounds fit even when the usable monitor is smaller than preferred or minimum`() {
        val area=Rectangle(40,20,320,240)
        assertEquals(area,ApprovalDialogBounds.initial(Dimension(1800,1200),Dimension(500,350),area,null))
        val resized=ApprovalDialogBounds.fit(Rectangle(-50,-40,270,190),area)
        assertEquals(Rectangle(40,20,270,190),resized)
    }

    @Test fun `review shows independent requested inputs and a narrowed selection as a mismatch despite an exclusion reason`() {
        val request=RequestPlan(endpoint("http://fixture.invalid/item"),"private raw bytes","source","digest",
            Json.parseToJsonElement("""{"insertionPointParameters":[{"name":"mode","type":"URL"},{"name":"user","type":"BODY"},{"name":"password","type":"BODY"}]}""").jsonObject)
        val selected=ScanVariant("reflection","REFLECTION",request=request,settings=SettingsPlan(),
            inputExclusions=listOf(InputExclusion("csrf","BODY","Will be tested in another future job")))
        val requested=listOf(InputParameter("mode","URL"),InputParameter("csrf","BODY"),
            InputParameter("user","BODY"),InputParameter("password","BODY"))
        val proposal=JobProposal(jobId="scope-review",revision=1,objective="all four requested inputs",
            targetPolicy=emptyList(),materials=emptyList(),session=SessionPlan(false,"OMIT","isolated login","account"),
            variants=listOf(selected),requiredCapabilities=emptySet(),cleanupPolicy="review owned state",
            requestedInputParameters=requested)
        val intent=reviewRequestedInputSummary(proposal)
        val choice=reviewVariantSummary(selected,requested)
        assertTrue(intent.contains("計画の独立宣言）：4項目"))
        requested.forEach { assertTrue(intent.contains("依頼入力：${it.name} [${it.type}]")) }
        assertTrue(intent.contains("原本のユーザー依頼と照合"))
        assertTrue(choice.contains("選択入力数：3項目"))
        assertTrue(choice.contains("依頼入力との一致：不一致（送信不可）"))
        assertFalse(intent.contains(request.request));assertFalse(choice.contains(request.request))
        assertTrue(reviewRequestedInputSummary(proposal.copy(requestedInputParameters=emptyList())).contains("旧保存計画"))
    }

    @Test fun `review summary exposes selected inputs exclusion reasons and separate once only preparation count without raw requests`() {
        val request=RequestPlan(endpoint("http://fixture.invalid/item"),"secret raw request bytes","source","digest")
        val automatic=ScanVariant("auto","native",request=request,settings=SettingsPlan())
        assertTrue(reviewVariantSummary(automatic).contains("自動選択（insertionPointParameters未指定）"))
        val selected=automatic.copy(request=request.copy(startOptions=Json.parseToJsonElement(
            """{"insertionPointParameters":[{"name":"comment","type":"body"}]}""").jsonObject),
            inputExclusions=listOf(InputExclusion("csrf","body","認証維持のため動的更新する")),preparationOnce=listOf(request))
        val text=reviewVariantSummary(selected)
        assertTrue(text.contains("診断入力：comment [body]"))
        assertTrue(text.contains("明示除外：csrf [body]、理由：認証維持のため動的更新する"))
        assertTrue(text.contains("開始前の一度だけの準備：1件"))
        assertTrue(text.contains("各リクエストのMacroとは別"))
        assertTrue(text.contains("5回以上の検証送信には数えません"))
        assertFalse(text.contains(request.request))
    }
}
