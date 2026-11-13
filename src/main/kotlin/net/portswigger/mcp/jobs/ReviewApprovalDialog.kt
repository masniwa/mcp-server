package net.portswigger.mcp.jobs

import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dialog
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.GraphicsEnvironment
import java.awt.Insets
import java.awt.Rectangle
import java.awt.Toolkit
import java.awt.Window
import java.awt.event.ActionEvent
import java.awt.event.ComponentAdapter
import java.awt.event.ComponentEvent
import java.awt.event.KeyEvent
import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
import javax.swing.*

internal data class ApprovalPage(val title:String,val text:String,val wrap:Boolean=true)

/** Only the review body scrolls; the explicit human decision stays outside it. */
internal class ReviewApprovalPanel(pages:List<ApprovalPage>,explanation:String,
    private val onDecision:(Boolean)->Unit) : JPanel(BorderLayout(0,12)) {
    val confirmation=JCheckBox("操作を許可する")
    val approve=JButton("OK")
    val cancel=JButton("Cancel")
    val footer=JPanel(BorderLayout(0,8))
    var decision:Boolean?=null
        private set
    private var approvalRoot:JRootPane?=null
    private val acceptAction=object:AbstractAction() {
        override fun actionPerformed(event:ActionEvent?) { accept() }
    }
    private val rejectAction=object:AbstractAction() {
        override fun actionPerformed(event:ActionEvent?) { reject() }
    }

    init {
        require(pages.isNotEmpty())
        border=BorderFactory.createEmptyBorder(12,12,12,12)
        val views=pages.map { page ->
            val area=JTextArea("$explanation\n\n${page.text}",18,72).apply {
                isEditable=false
                lineWrap=page.wrap
                wrapStyleWord=true
                caretPosition=0
            }
            JScrollPane(area).apply { minimumSize=Dimension(0,0) }
        }
        val body=if(views.size==1) views.single() else JTabbedPane().apply {
            tabLayoutPolicy=JTabbedPane.SCROLL_TAB_LAYOUT
            pages.zip(views).forEach { (page,view) -> addTab(page.title,view) }
            minimumSize=Dimension(0,0)
        }
        add(body,BorderLayout.CENTER)
        footer.add(confirmation,BorderLayout.NORTH)
        footer.add(JPanel(FlowLayout(FlowLayout.TRAILING,8,0)).apply {
            add(approve);add(cancel)
        },BorderLayout.SOUTH)
        add(footer,BorderLayout.SOUTH)
        approve.isEnabled=false
        acceptAction.isEnabled=false
        confirmation.addItemListener {
            approve.isEnabled=confirmation.isSelected
            acceptAction.isEnabled=confirmation.isSelected
            approvalRoot?.defaultButton=if(confirmation.isSelected) approve else null
        }
        approve.addActionListener { accept() }
        cancel.addActionListener { reject() }
    }

    fun installKeys(root:JRootPane) {
        approvalRoot=root
        root.defaultButton=if(confirmation.isSelected) approve else null
        root.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).apply {
            put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER,0),"acceptReviewApproval")
            put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE,0),"rejectReviewApproval")
        }
        root.actionMap.put("acceptReviewApproval",acceptAction)
        root.actionMap.put("rejectReviewApproval",rejectAction)
        // Enter on the focused Cancel button retains its normal cancellation meaning.
        cancel.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER,0),"rejectReviewApproval")
        cancel.actionMap.put("rejectReviewApproval",rejectAction)
    }

    private fun accept() {
        // Recheck here too: a default key or an ActionEvent must not bypass the checkbox.
        if(confirmation.isSelected) finish(true)
    }

    fun reject() { finish(false) }

    private fun finish(accepted:Boolean) {
        if(decision!=null) return
        decision=accepted
        onDecision(accepted)
    }
}

/** Pure geometry also covers monitors left/above the primary display and taskbar insets. */
internal object ApprovalDialogBounds {
    fun usable(screen:Rectangle,insets:Insets)=Rectangle(
        screen.x+insets.left,screen.y+insets.top,
        (screen.width-insets.left-insets.right).coerceAtLeast(1),
        (screen.height-insets.top-insets.bottom).coerceAtLeast(1))

    fun fit(requested:Rectangle,workArea:Rectangle):Rectangle {
        val width=requested.width.coerceIn(1,workArea.width)
        val height=requested.height.coerceIn(1,workArea.height)
        return Rectangle(
            requested.x.coerceIn(workArea.x,workArea.x+workArea.width-width),
            requested.y.coerceIn(workArea.y,workArea.y+workArea.height-height),width,height)
    }

    fun initial(preferred:Dimension,minimum:Dimension,workArea:Rectangle,owner:Rectangle?):Rectangle {
        val width=preferred.width.coerceAtMost(1000).coerceAtLeast(minimum.width).coerceAtMost(workArea.width)
        val height=preferred.height.coerceAtMost(760).coerceAtLeast(minimum.height).coerceAtMost(workArea.height)
        val center=owner ?: workArea
        return fit(Rectangle(center.x+(center.width-width)/2,center.y+(center.height-height)/2,width,height),workArea)
    }
}

internal object ReviewApprovalDialog {
    fun show(owner:Component?,title:String,pages:List<ApprovalPage>,explanation:String):Boolean {
        check(SwingUtilities.isEventDispatchThread())
        val window=owner as? Window ?: owner?.let { SwingUtilities.getWindowAncestor(it) }
        val configuration=window?.graphicsConfiguration ?: owner?.graphicsConfiguration
            ?: GraphicsEnvironment.getLocalGraphicsEnvironment().defaultScreenDevice.defaultConfiguration
        val workArea=ApprovalDialogBounds.usable(configuration.bounds,Toolkit.getDefaultToolkit().getScreenInsets(configuration))
        val dialog=JDialog(window,title,Dialog.ModalityType.APPLICATION_MODAL).apply {
            isResizable=true
            defaultCloseOperation=WindowConstants.DO_NOTHING_ON_CLOSE
        }
        val panel=ReviewApprovalPanel(pages,explanation) { dialog.dispose() }
        try {
            dialog.contentPane=panel
            panel.installKeys(dialog.rootPane)
            dialog.addWindowListener(object:WindowAdapter() {
                override fun windowClosing(event:WindowEvent) { panel.reject() }
            })
            dialog.pack()
            val decoration=dialog.insets
            val minimum=Dimension(
                (panel.minimumSize.width+decoration.left+decoration.right).coerceAtMost(workArea.width),
                (panel.minimumSize.height+decoration.top+decoration.bottom+100).coerceAtMost(workArea.height))
            dialog.minimumSize=minimum
            dialog.maximumSize=workArea.size
            dialog.bounds=ApprovalDialogBounds.initial(dialog.preferredSize,minimum,workArea,window?.bounds)
            dialog.addComponentListener(object:ComponentAdapter() {
                override fun componentResized(event:ComponentEvent) {
                    // Moving remains unrestricted; resizing follows the dialog's current monitor.
                    val current=dialog.graphicsConfiguration ?: configuration
                    val currentArea=ApprovalDialogBounds.usable(current.bounds,Toolkit.getDefaultToolkit().getScreenInsets(current))
                    dialog.maximumSize=currentArea.size
                    val currentMinimum=Dimension(
                        (panel.minimumSize.width+decoration.left+decoration.right).coerceAtMost(currentArea.width),
                        (panel.minimumSize.height+decoration.top+decoration.bottom+100).coerceAtMost(currentArea.height))
                    if(currentMinimum!=dialog.minimumSize) dialog.minimumSize=currentMinimum
                    val fitted=ApprovalDialogBounds.fit(dialog.bounds,currentArea)
                    if(fitted!=dialog.bounds) dialog.bounds=fitted
                }
            })
            SwingUtilities.invokeLater { panel.confirmation.requestFocusInWindow() }
            dialog.isVisible=true
            return panel.decision==true
        } finally { dialog.dispose() }
    }
}
