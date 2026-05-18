package com.llmredactor.burp.ui

import com.llmredactor.burp.config.PluginConfig
import com.llmredactor.burp.detect.Span
import com.llmredactor.burp.transport.SessionStore
import com.llmredactor.burp.transport.Stats
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.awt.GridLayout
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import javax.swing.BorderFactory
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JTable
import javax.swing.SwingUtilities
import javax.swing.border.EmptyBorder
import javax.swing.filechooser.FileNameExtensionFilter
import javax.swing.table.DefaultTableModel

/**
 * Activity log with metric cards, styled table, and export.
 *
 * Log rows are capped at [PluginConfig.logRowCap] (newest first); older rows drop off automatically.
 */
class LogPanel(
    private val config: PluginConfig,
    private val stats: Stats,
    private val store: SessionStore,
) : JPanel(BorderLayout()) {

    private val timeFormat = SimpleDateFormat("HH:mm:ss")

    private val tableModel = object : DefaultTableModel(
        arrayOf("Time", "Host", "Path", "Spans", "Kinds"),
        0,
    ) {
        override fun isCellEditable(row: Int, col: Int) = false
    }
    private val table = JTable(tableModel)

    private val cardRequests = StatCard("Requests", UiTheme.accent)
    private val cardSpans = StatCard("Spans redacted", UiTheme.accent)
    private val cardRestores = StatCard("Restores", UiTheme.warn)
    private val cardRefusals = StatCard("Refusals", UiTheme.danger)
    private val cardEvictions = StatCard("Evictions", UiTheme.textMuted)
    private val retentionHint = UiTheme.dimLabel("")

    init {
        UiTheme.styleRoot(this)
        UiTheme.styleTable(table)

        table.autoResizeMode = JTable.AUTO_RESIZE_ALL_COLUMNS
        table.preferredScrollableViewportSize = java.awt.Dimension(800, 280)
        table.columnModel.getColumn(0).preferredWidth = 80
        table.columnModel.getColumn(1).minWidth = 120
        table.columnModel.getColumn(2).minWidth = 160
        table.columnModel.getColumn(3).preferredWidth = 56
        table.columnModel.getColumn(4).minWidth = 200

        val dashboard = JPanel(GridLayout(1, 0, 10, 0)).apply {
            isOpaque = false
        }
        dashboard.add(cardRequests)
        dashboard.add(cardSpans)
        dashboard.add(cardRestores)
        dashboard.add(cardRefusals)
        dashboard.add(cardEvictions)

        val logHeader = JPanel(BorderLayout()).apply {
            isOpaque = false
            border = EmptyBorder(12, 0, 8, 0)
        }
        val logTitleBlock = JPanel().apply {
            layout = javax.swing.BoxLayout(this, javax.swing.BoxLayout.Y_AXIS)
            isOpaque = false
            add(JLabel("Recent redactions").apply {
                font = UiTheme.fontBody.deriveFont(java.awt.Font.BOLD, 13f)
                foreground = UiTheme.textColor
                alignmentX = java.awt.Component.LEFT_ALIGNMENT
            })
            add(retentionHint.apply {
                border = EmptyBorder(4, 0, 0, 0)
                alignmentX = java.awt.Component.LEFT_ALIGNMENT
            })
        }
        logHeader.add(logTitleBlock, BorderLayout.WEST)

        val btnClear = UiTheme.secondaryButton("Clear")
        btnClear.addActionListener {
            tableModel.rowCount = 0
            stats.reset()
            store.resetEvictionCounter()
            refreshStats()
        }
        val btnExport = UiTheme.secondaryButton("Export CSV")
        btnExport.addActionListener { exportCsv() }

        logHeader.add(
            JPanel(FlowLayout(FlowLayout.RIGHT, 8, 0)).apply {
                isOpaque = false
                add(btnClear)
                add(btnExport)
            },
            BorderLayout.EAST,
        )

        val north = JPanel(BorderLayout()).apply {
            isOpaque = false
            border = EmptyBorder(12, 16, 0, 16)
            add(dashboard, BorderLayout.NORTH)
            add(logHeader, BorderLayout.SOUTH)
        }

        val logSection = CollapsibleSection("Activity log", "Per-request redaction and refusal events", true)
        val tableScroll = UiTheme.scrollPane(table).apply {
            border = BorderFactory.createCompoundBorder(
                UiTheme.roundedBorder(6),
                BorderFactory.createEmptyBorder(1, 1, 1, 1),
            )
            preferredSize = java.awt.Dimension(0, 280)
        }
        logSection.body().apply {
            layout = BorderLayout()
            add(tableScroll, BorderLayout.CENTER)
        }

        val center = JPanel(BorderLayout()).apply {
            isOpaque = false
            border = EmptyBorder(8, 16, 16, 16)
            add(logSection, BorderLayout.CENTER)
        }

        add(north, BorderLayout.NORTH)
        add(center, BorderLayout.CENTER)

        refreshRetentionHint()
        refreshStats()
    }

    fun refreshRetentionHint() {
        retentionHint.text = "Newest first · keeps last ${config.logRowCap.coerceIn(50, 10_000)} rows"
    }

    /** Visible activity rows (for tests). Must be called on the EDT. */
    fun activityRowCount(): Int = tableModel.rowCount

    /** Test-only: insert on current thread (no invokeLater). */
    internal fun addActivityRowNow(host: String, path: String, spanCount: Int, kinds: String) {
        val time = timeFormat.format(Date())
        insertRow(arrayOf(time, host, path, spanCount.toString(), kinds))
    }

    internal fun getPathAt(row: Int): String = tableModel.getValueAt(row, 2).toString()

    internal fun retentionHintText(): String = retentionHint.text

    fun addRefusedReason(host: String, path: String, reason: String) {
        val time = timeFormat.format(Date())
        SwingUtilities.invokeLater {
            insertRow(arrayOf(time, host, path, "0", "REFUSED $reason"))
        }
    }

    fun addRefusedEntry(host: String, path: String, lowConfidenceSpans: List<Span>) {
        val kinds = lowConfidenceSpans
            .groupingBy { it.kind }
            .eachCount()
            .entries
            .joinToString(", ") { (k, v) -> "$k×$v" }
        val time = timeFormat.format(Date())
        SwingUtilities.invokeLater {
            insertRow(arrayOf(time, host, path, "0", "REFUSED low_confidence: $kinds"))
        }
    }

    fun addEntry(host: String, path: String, spanCount: Int, kindCounts: Map<String, Int>) {
        val kinds = kindCounts.entries.joinToString(", ") { (k, v) -> "$k×$v" }
        addActivityRow(host, path, spanCount, kinds)
    }

    fun addActivityRow(host: String, path: String, spanCount: Int, kinds: String) {
        val time = timeFormat.format(Date())
        SwingUtilities.invokeLater {
            insertRow(arrayOf(time, host, path, spanCount.toString(), kinds))
        }
    }

    fun refreshStats() {
        cardRequests.setValue(stats.requests.get().toString())
        cardSpans.setValue(stats.spansRedacted.get().toString())
        cardRestores.setValue(stats.restores.get().toString())
        cardRefusals.setValue(stats.refusals.get().toString())
        cardEvictions.setValue(store.evictions.toString())
    }

    private fun insertRow(row: Array<String>) {
        tableModel.insertRow(0, row)
        val cap = config.logRowCap.coerceIn(50, 10_000)
        while (tableModel.rowCount > cap) {
            tableModel.removeRow(tableModel.rowCount - 1)
        }
        refreshStats()
    }

    private fun exportCsv() {
        val chooser = javax.swing.JFileChooser().apply {
            selectedFile = File("llm-redactor-log.csv")
            fileFilter = FileNameExtensionFilter("CSV files", "csv")
        }
        if (chooser.showSaveDialog(this) != javax.swing.JFileChooser.APPROVE_OPTION) return
        try {
            chooser.selectedFile.bufferedWriter().use { w ->
                w.write("Time,Host,Path,Spans,Kinds\n")
                for (r in 0 until tableModel.rowCount) {
                    val cols = (0 until tableModel.columnCount).joinToString(",") { col ->
                        "\"${tableModel.getValueAt(r, col)}\""
                    }
                    w.write("$cols\n")
                }
            }
            JOptionPane.showMessageDialog(
                this,
                "Exported to ${chooser.selectedFile.absolutePath}",
                "Export",
                JOptionPane.INFORMATION_MESSAGE,
            )
        } catch (e: Exception) {
            JOptionPane.showMessageDialog(
                this,
                "Export failed: ${e.message}",
                "Export",
                JOptionPane.ERROR_MESSAGE,
            )
        }
    }

}
