package com.llmredactor.burp.ui

import java.awt.Color
import java.awt.Cursor
import java.awt.Font
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.RenderingHints
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.JButton
import javax.swing.border.EmptyBorder

/**
 * Flat button with rounded fill and explicit normal/hover colors.
 */
class RoundedButton(
    label: String,
    private val cornerRadius: Int = 8,
    normalBg: Color,
    hoverBg: Color,
    labelColor: Color = Color.WHITE,
) : JButton(label) {

    private var fillBg: Color = normalBg

    init {
        font = UiTheme.fontBody.deriveFont(Font.BOLD)
        foreground = labelColor
        isOpaque = false
        isContentAreaFilled = false
        isBorderPainted = false
        isFocusPainted = false
        border = EmptyBorder(6, 18, 6, 18)
        cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)

        fun applyNormal() {
            fillBg = normalBg
            repaint()
        }

        fun applyHover() {
            fillBg = hoverBg
            repaint()
        }

        applyNormal()
        addMouseListener(object : MouseAdapter() {
            override fun mouseEntered(e: MouseEvent?) = applyHover()
            override fun mouseExited(e: MouseEvent?) = applyNormal()
        })
    }

    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        val arc = cornerRadius * 2
        g2.color = fillBg
        g2.fillRoundRect(0, 0, width, height, arc, arc)
        g2.dispose()
        super.paintComponent(g)
    }
}
