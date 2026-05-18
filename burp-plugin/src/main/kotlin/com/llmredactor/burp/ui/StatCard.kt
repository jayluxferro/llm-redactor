package com.llmredactor.burp.ui

import java.awt.BorderLayout
import java.awt.Color
import java.awt.Dimension
import java.awt.Font
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.border.CompoundBorder
import javax.swing.border.EmptyBorder

/** Compact metric tile for the log dashboard. */
class StatCard(
    title: String,
    accentColor: Color = UiTheme.accent,
) : JPanel(BorderLayout()) {

    private val lblValue = JLabel("0")

    init {
        background = UiTheme.surface
        isOpaque = true
        border = CompoundBorder(
            UiTheme.roundedBorder(8),
            EmptyBorder(12, 14, 12, 14),
        )
        preferredSize = Dimension(110, 72)
        minimumSize = Dimension(96, 72)

        lblValue.apply {
            font = UiTheme.fontTitle.deriveFont(Font.BOLD, 22f)
            foreground = accentColor
        }
        val lblTitle = JLabel(title).apply {
            font = UiTheme.fontSmall
            foreground = UiTheme.textMuted
            border = EmptyBorder(4, 0, 0, 0)
        }
        add(lblValue, BorderLayout.CENTER)
        add(lblTitle, BorderLayout.SOUTH)
    }

    fun setValue(value: String) {
        lblValue.text = value
    }
}
