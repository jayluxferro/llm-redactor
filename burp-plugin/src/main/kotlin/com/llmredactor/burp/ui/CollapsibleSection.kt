package com.llmredactor.burp.ui

import java.awt.BorderLayout
import java.awt.Component
import java.awt.Cursor
import java.awt.Font
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.border.CompoundBorder
import javax.swing.border.EmptyBorder

/**
 * Card section with a clickable header that expands/collapses the body.
 */
class CollapsibleSection(
    title: String,
    subtitle: String? = null,
    initiallyExpanded: Boolean = true,
) : JPanel(BorderLayout()) {

    private val chevron = JLabel()
    private val bodyWrapper = JPanel(BorderLayout())
    private val body = JPanel().apply {
        layout = javax.swing.BoxLayout(this, javax.swing.BoxLayout.Y_AXIS)
        isOpaque = false
        alignmentX = Component.LEFT_ALIGNMENT
    }

    private var expanded = initiallyExpanded

    init {
        background = UiTheme.surface
        isOpaque = true
        alignmentX = Component.LEFT_ALIGNMENT
        border = CompoundBorder(
            UiTheme.roundedBorder(10),
            EmptyBorder(0, 0, 0, 0),
        )

        val header = JPanel(BorderLayout(8, 0)).apply {
            isOpaque = false
            cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
            border = EmptyBorder(12, 14, 12, 14)
        }

        chevron.font = UiTheme.fontBody
        chevron.foreground = UiTheme.accent

        val titles = JPanel().apply {
            layout = javax.swing.BoxLayout(this, javax.swing.BoxLayout.Y_AXIS)
            isOpaque = false
            add(JLabel(title).apply {
                font = UiTheme.fontBody.deriveFont(Font.BOLD, 13f)
                foreground = UiTheme.textColor
                alignmentX = Component.LEFT_ALIGNMENT
            })
            if (subtitle != null) {
                add(UiTheme.mutedLabel(subtitle).apply {
                    border = EmptyBorder(4, 0, 0, 0)
                    alignmentX = Component.LEFT_ALIGNMENT
                })
            }
        }

        header.add(chevron, BorderLayout.WEST)
        header.add(titles, BorderLayout.CENTER)

        header.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent?) = toggle()
        })
        chevron.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent?) = toggle()
        })

        bodyWrapper.isOpaque = false
        bodyWrapper.border = EmptyBorder(0, 16, 14, 16)
        bodyWrapper.add(body, BorderLayout.CENTER)

        maximumSize = java.awt.Dimension(Int.MAX_VALUE, Int.MAX_VALUE)
        add(header, BorderLayout.NORTH)
        add(bodyWrapper, BorderLayout.CENTER)
        applyExpanded()
    }

    fun body(): JPanel = body

    private fun toggle() {
        expanded = !expanded
        applyExpanded()
    }

    private fun applyExpanded() {
        bodyWrapper.isVisible = expanded
        chevron.text = if (expanded) "▾" else "▸"
        revalidate()
        repaint()
    }
}
