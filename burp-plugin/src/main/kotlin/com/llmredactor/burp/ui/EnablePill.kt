package com.llmredactor.burp.ui

import java.awt.BorderLayout
import java.awt.Cursor
import java.awt.Dimension
import java.awt.Font
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.border.CompoundBorder
import javax.swing.border.EmptyBorder

/** Clickable on/off pill for global intercept toggle. */
class EnablePill(
    initialOn: Boolean,
    private val onToggle: (Boolean) -> Unit,
) : JPanel() {

    private val lbl = JLabel()
    private var on = initialOn

    init {
        layout = BorderLayout()
        isOpaque = true
        cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
        preferredSize = Dimension(118, 34)
        minimumSize = Dimension(118, 34)
        maximumSize = Dimension(118, 34)
        lbl.font = UiTheme.fontBody.deriveFont(Font.BOLD, 12f)
        lbl.horizontalAlignment = JLabel.CENTER
        add(lbl, BorderLayout.CENTER)
        paintState()
        addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent?) {
                on = !on
                paintState()
                onToggle(on)
            }
        })
    }

    fun setOn(enabled: Boolean) {
        on = enabled
        paintState()
    }

    private fun paintState() {
        if (on) {
            background = UiTheme.accentMuted
            border = CompoundBorder(
                UiTheme.roundedBorder(17, UiTheme.accent),
                EmptyBorder(8, 16, 8, 16),
            )
            lbl.text = "● Live"
            lbl.foreground = UiTheme.accent
        } else {
            background = UiTheme.dangerMuted
            border = CompoundBorder(
                UiTheme.roundedBorder(17, UiTheme.danger),
                EmptyBorder(8, 16, 8, 16),
            )
            lbl.text = "○ Paused"
            lbl.foreground = UiTheme.danger
        }
    }
}
