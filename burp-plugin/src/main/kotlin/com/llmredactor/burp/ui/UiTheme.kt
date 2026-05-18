package com.llmredactor.burp.ui

import java.awt.Color
import java.awt.Component
import java.awt.Dimension
import java.awt.Font
import java.awt.Insets
import javax.swing.Box
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSpinner
import javax.swing.JTable
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.SwingConstants
import javax.swing.UIManager
import javax.swing.border.AbstractBorder
import javax.swing.border.CompoundBorder
import javax.swing.border.EmptyBorder
import javax.swing.table.DefaultTableCellRenderer
import javax.swing.table.JTableHeader

/** Burp-friendly dark palette and shared styling helpers. */
object UiTheme {

    /** PortSwigger / Burp Suite orange. */
    val burpOrange = Color(255, 102, 0)

    val accent = burpOrange
    val accentHover = Color(255, 130, 40)
    val accentMuted = Color(72, 38, 18)

    val danger = Color(235, 96, 96)
    val dangerMuted = Color(120, 48, 48)

    val warn = Color(240, 178, 72)

    /** Primary button hover — Burp dark chrome. */
    private val primaryHoverBg = Color(45, 48, 52)
    private val primaryLabelOnAccent = Color.WHITE

    val bg: Color
    val surface: Color
    val surfaceRaised: Color
    val border: Color
    val borderFocus: Color
    val textColor: Color
    val textMuted: Color
    val textDim: Color

    val fontTitle: Font
    val fontBody: Font
    val fontSmall: Font
    val fontMono: Font

    init {
        val uiBg = UIManager.getColor("Panel.background")
        val dark = uiBg == null || uiBg.red < 128
        if (dark) {
            bg = Color(36, 38, 41)
            surface = Color(46, 49, 53)
            surfaceRaised = Color(56, 60, 65)
            border = Color(70, 74, 80)
            borderFocus = Color(255, 102, 0, 180)
            textColor = Color(225, 228, 232)
            textMuted = Color(155, 160, 168)
            textDim = Color(110, 115, 122)
        } else {
            bg = Color(245, 246, 248)
            surface = Color(255, 255, 255)
            surfaceRaised = Color(252, 252, 253)
            border = Color(210, 214, 220)
            borderFocus = Color(255, 102, 0, 160)
            textColor = Color(32, 34, 38)
            textMuted = Color(95, 100, 108)
            textDim = Color(130, 135, 142)
        }
        val base = UIManager.getFont("Label.font") ?: Font(Font.SANS_SERIF, Font.PLAIN, 12)
        fontTitle = base.deriveFont(Font.BOLD, 15f)
        fontBody = base.deriveFont(Font.PLAIN, 12f)
        fontSmall = base.deriveFont(Font.PLAIN, 11f)
        fontMono = Font(Font.MONOSPACED, Font.PLAIN, 11)
    }

    fun styleRoot(panel: JPanel) {
        panel.background = bg
        panel.isOpaque = true
    }

    fun sectionPanel(title: String, subtitle: String? = null): JPanel {
        val outer = JPanel()
        outer.layout = java.awt.BorderLayout(0, 6)
        outer.background = surface
        outer.isOpaque = true
        outer.border = CompoundBorder(
            roundedBorder(10),
            EmptyBorder(14, 16, 14, 16),
        )

        val head = JPanel(java.awt.BorderLayout())
        head.isOpaque = false
        val titleLbl = JLabel(title).apply {
            font = fontBody.deriveFont(Font.BOLD, 13f)
            foreground = textColor
        }
        head.add(titleLbl, java.awt.BorderLayout.NORTH)
        if (subtitle != null) {
            head.add(
                mutedLabel(subtitle).apply {
                    border = EmptyBorder(4, 0, 0, 0)
                },
                java.awt.BorderLayout.SOUTH,
            )
        }
        outer.add(head, java.awt.BorderLayout.NORTH)
        return outer
    }

    const val FORM_MAX_WIDTH = 720
    const val WIDTH_FULL = 640
    const val WIDTH_URL = 480
    const val WIDTH_MEDIUM = 280
    const val WIDTH_COMBO = 168

    fun sectionBody(section: JPanel): JPanel {
        val body = JPanel()
        body.layout = javax.swing.BoxLayout(body, javax.swing.BoxLayout.Y_AXIS)
        body.isOpaque = false
        body.border = EmptyBorder(12, 0, 0, 0)
        body.alignmentX = Component.LEFT_ALIGNMENT
        section.add(body, java.awt.BorderLayout.CENTER)
        section.alignmentX = Component.LEFT_ALIGNMENT
        return body
    }

    fun sectionInForm(section: JPanel): JPanel {
        section.alignmentX = Component.LEFT_ALIGNMENT
        section.maximumSize = Dimension(FORM_MAX_WIDTH, Int.MAX_VALUE)
        return section
    }

    /** Prevents BoxLayout from stretching a row to full viewport width. */
    fun boxRow(component: Component): JPanel {
        val row = JPanel(java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 0, 0))
        row.isOpaque = false
        row.alignmentX = Component.LEFT_ALIGNMENT
        row.add(component)
        capRowHeight(row)
        return row
    }

    fun leftRow(gap: Int = 8, vararg components: Component): JPanel {
        val row = JPanel(java.awt.FlowLayout(java.awt.FlowLayout.LEFT, gap, 0))
        row.isOpaque = false
        row.alignmentX = Component.LEFT_ALIGNMENT
        components.forEach { row.add(it) }
        capRowHeight(row)
        return row
    }

    fun capRowHeight(row: JPanel) {
        row.maximumSize = Dimension(Int.MAX_VALUE, row.preferredSize.height)
    }

    fun constrain(component: JComponent, width: Int, height: Int? = null): JComponent {
        val h = height ?: component.preferredSize.height.coerceAtLeast(30)
        val size = Dimension(width, h)
        component.preferredSize = size
        component.minimumSize = size
        component.maximumSize = size
        return component
    }

    fun fieldLabel(text: String, hint: String? = null): JPanel {
        val p = JPanel()
        p.layout = javax.swing.BoxLayout(p, javax.swing.BoxLayout.Y_AXIS)
        p.isOpaque = false
        p.alignmentX = Component.LEFT_ALIGNMENT
        p.add(JLabel(text).apply {
            font = fontSmall.deriveFont(Font.BOLD)
            foreground = textMuted
            alignmentX = Component.LEFT_ALIGNMENT
        })
        if (hint != null) {
            p.add(Box.createVerticalStrut(2))
            p.add(dimLabel(hint).apply {
                alignmentX = Component.LEFT_ALIGNMENT
            })
        }
        p.border = EmptyBorder(0, 0, 6, 0)
        capRowHeight(p)
        return p
    }

    fun bodyRow(body: JPanel, component: Component) {
        body.add(boxRow(component))
    }

    fun styleField(field: JTextField) {
        field.font = fontMono
        field.background = surfaceRaised
        field.foreground = textColor
        field.caretColor = accent
        field.border = CompoundBorder(roundedBorder(6), EmptyBorder(8, 10, 8, 10))
    }

    fun styleTextArea(area: JTextArea) {
        area.font = fontMono
        area.background = surfaceRaised
        area.foreground = textColor
        area.caretColor = accent
        area.lineWrap = true
        area.wrapStyleWord = true
        area.border = EmptyBorder(8, 10, 8, 10)
    }

    fun styleCombo(box: JComboBox<*>) {
        box.font = fontBody
        box.background = surfaceRaised
        box.foreground = textColor
    }

    fun styleSpinner(spinner: JSpinner) {
        spinner.font = fontMono
    }

    fun styleCheck(box: JCheckBox) {
        box.font = fontBody
        box.foreground = textColor
        box.isOpaque = false
    }

    fun primaryButton(label: String): JButton =
        RoundedButton(
            label = label,
            cornerRadius = 8,
            normalBg = accent,
            hoverBg = primaryHoverBg,
            labelColor = primaryLabelOnAccent,
        )

    fun secondaryButton(label: String): JButton = JButton(label).apply {
        font = fontBody
        foreground = textColor
        background = surfaceRaised
        isOpaque = true
        isBorderPainted = true
        isFocusPainted = false
        border = CompoundBorder(roundedBorder(6), EmptyBorder(8, 14, 8, 14))
        cursor = java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.HAND_CURSOR)
    }

    fun scrollPane(view: Component): JScrollPane = JScrollPane(view).apply {
        border = BorderFactory.createEmptyBorder()
        background = bg
        viewport.background = bg
        horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED
        verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
    }

    fun vGap(h: Int) = Box.createVerticalStrut(h)

    fun mutedLabel(text: String): JLabel = JLabel(text).apply {
        font = fontSmall
        foreground = textMuted
    }

    fun dimLabel(text: String): JLabel = JLabel(text).apply {
        font = fontSmall
        foreground = textDim
    }

    fun styleTable(table: JTable) {
        table.background = surface
        table.foreground = textColor
        table.font = fontMono
        table.rowHeight = 28
        table.showVerticalLines = true
        table.showHorizontalLines = true
        table.gridColor = border
        table.intercellSpacing = Dimension(1, 1)
        val line = border
        table.border = BorderFactory.createLineBorder(line)
        table.tableHeader.let { header ->
            header.background = surfaceRaised
            header.foreground = textMuted
            header.font = fontSmall.deriveFont(Font.BOLD)
            header.reorderingAllowed = false
            header.border = BorderFactory.createMatteBorder(0, 0, 1, 0, line)
            header.setDefaultRenderer(object : DefaultTableCellRenderer() {
                override fun getTableCellRendererComponent(
                    table: JTable?, value: Any?, isSelected: Boolean, hasFocus: Boolean,
                    row: Int, column: Int,
                ): java.awt.Component {
                    val c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
                    if (c is JLabel) {
                        c.border = BorderFactory.createCompoundBorder(
                            BorderFactory.createMatteBorder(0, 0, 0, 1, line),
                            EmptyBorder(8, 10, 8, 10),
                        )
                        c.horizontalAlignment = SwingConstants.LEFT
                    }
                    return c
                }
            })
        }
        table.setDefaultRenderer(
            Any::class.java,
            object : DefaultTableCellRenderer() {
                override fun getTableCellRendererComponent(
                    table: JTable?, value: Any?, isSelected: Boolean, hasFocus: Boolean,
                    row: Int, column: Int,
                ): java.awt.Component {
                    val c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
                    if (c is JLabel) {
                        c.border = BorderFactory.createCompoundBorder(
                            BorderFactory.createMatteBorder(0, 0, 0, 1, line),
                            EmptyBorder(4, 10, 4, 10),
                        )
                        val kinds = value?.toString().orEmpty()
                        if (!isSelected && kinds.startsWith("REFUSED")) {
                            c.foreground = warn
                        } else if (!isSelected) {
                            c.foreground = textColor
                        }
                        if (!isSelected && row % 2 == 1) {
                            c.background = surfaceRaised
                        }
                    }
                    if (isSelected) {
                        c.background = accentMuted
                        c.foreground = textColor
                    }
                    return c
                }
            },
        )
    }

    fun roundedBorder(radius: Int = 8, color: Color = border): javax.swing.border.Border =
        RoundedBorder(radius, color)

    class RoundedBorder(private val radius: Int, private val color: Color) : AbstractBorder() {
        override fun paintBorder(c: Component, g: java.awt.Graphics, x: Int, y: Int, w: Int, h: Int) {
            val g2 = g.create() as java.awt.Graphics2D
            g2.setRenderingHint(java.awt.RenderingHints.KEY_ANTIALIASING, java.awt.RenderingHints.VALUE_ANTIALIAS_ON)
            g2.color = color
            g2.drawRoundRect(x, y, w - 1, h - 1, radius, radius)
            g2.dispose()
        }

        override fun getBorderInsets(c: Component) = Insets(1, 1, 1, 1)
    }
}
