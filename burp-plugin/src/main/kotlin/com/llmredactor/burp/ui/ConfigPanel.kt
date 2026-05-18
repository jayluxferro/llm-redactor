package com.llmredactor.burp.ui

import com.llmredactor.burp.config.PluginConfig
import com.llmredactor.burp.transport.NerClient
import com.llmredactor.burp.transport.SessionStore
import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSpinner
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.SpinnerNumberModel
import javax.swing.border.EmptyBorder

/**
 * Scrollable settings with grouped sections and a fixed apply bar.
 */
class ConfigPanel(
    private val config: PluginConfig,
    private val store: SessionStore,
    private val onSettingsSaved: () -> Unit = {},
) : JPanel(BorderLayout()) {

    private val txtHosts = JTextArea(config.targetHosts.joinToString("\n"), 4, 40)
    private val txtPaths = JTextArea(config.targetPaths.joinToString("\n"), 3, 40)
    private val chkPii = JCheckBox("PII", "pii" in config.categories)
    private val chkSecrets = JCheckBox("Secrets", "secret" in config.categories)
    private val chkOrgIds = JCheckBox("Org IDs", "org_identifier" in config.categories)
    private val chkAll = JCheckBox("All categories", "all" in config.categories)
    private val txtNerEndpoint = JTextField(config.nerEndpoint, 40)
    private val cmbToolsPolicy = JComboBox(arrayOf("bypass", "refuse"))
    private val chkStrict = JCheckBox("Strict mode", config.strict)
    private val chkPhTag = JCheckBox("Placeholder tags", config.placeholderTag)
    private val chkDebug = JCheckBox("Debug dump", config.debugDump)
    private val chkRestoreResp = JCheckBox("Restore in responses", config.restoreResponses)
    private val chkLlmValidation = JCheckBox("LLM validate NER spans", config.llmValidationEnabled)
    private val txtOllamaEndpoint = JTextField(config.ollamaEndpoint, 32)
    private val txtOllamaModel = JTextField(config.ollamaModel, 16)
    private val spnSessionCap = JSpinner(SpinnerNumberModel(config.sessionCap, 10, 100_000, 100))
    private val spnLogRowCap = JSpinner(SpinnerNumberModel(config.logRowCap, 50, 10_000, 50))
    private val chkLogMatched = JCheckBox("Log matched requests (incl. 0 spans)", config.logMatchedRequests)

    init {
        UiTheme.styleRoot(this)
        cmbToolsPolicy.selectedItem = config.toolsPolicy.lowercase()

        listOf(txtHosts, txtPaths).forEach(UiTheme::styleTextArea)
        listOf(txtNerEndpoint, txtOllamaEndpoint, txtOllamaModel).forEach(UiTheme::styleField)
        UiTheme.styleCombo(cmbToolsPolicy)
        UiTheme.constrain(cmbToolsPolicy, UiTheme.WIDTH_COMBO)
        UiTheme.constrain(txtNerEndpoint, UiTheme.WIDTH_URL)
        UiTheme.constrain(txtOllamaEndpoint, UiTheme.WIDTH_URL)
        UiTheme.constrain(txtOllamaModel, UiTheme.WIDTH_MEDIUM)
        UiTheme.styleSpinner(spnSessionCap)
        UiTheme.constrain(spnSessionCap, 120)
        UiTheme.styleSpinner(spnLogRowCap)
        UiTheme.constrain(spnLogRowCap, 120)
        listOf(
            chkPii, chkSecrets, chkOrgIds, chkAll, chkStrict, chkPhTag,
            chkDebug, chkRestoreResp, chkLlmValidation, chkLogMatched,
        ).forEach(UiTheme::styleCheck)

        val form = JPanel().apply {
            layout = javax.swing.BoxLayout(this, javax.swing.BoxLayout.Y_AXIS)
            isOpaque = false
            border = EmptyBorder(12, 16, 16, 16)
            alignmentX = Component.LEFT_ALIGNMENT
        }

        form.add(UiTheme.sectionInForm(buildScopeSection()))
        form.add(UiTheme.vGap(12))
        form.add(UiTheme.sectionInForm(buildDetectionSection()))
        form.add(UiTheme.vGap(12))
        form.add(UiTheme.sectionInForm(buildPolicySection()))
        form.add(UiTheme.vGap(12))
        form.add(UiTheme.sectionInForm(buildAdvancedSection()))
        form.add(Box.createVerticalGlue())

        add(UiTheme.scrollPane(form), BorderLayout.CENTER)
        add(buildFooter(), BorderLayout.SOUTH)

        chkAll.addActionListener {
            val sel = chkAll.isSelected
            chkPii.isEnabled = !sel
            chkSecrets.isEnabled = !sel
            chkOrgIds.isEnabled = !sel
        }
    }

    private fun buildScopeSection(): CollapsibleSection {
        val section = CollapsibleSection(
            "Scope",
            "Hosts and paths that trigger outbound redaction (one per line or comma-separated).",
            initiallyExpanded = true,
        )
        val body = section.body()
        UiTheme.bodyRow(body, fieldBlock("Target hosts", txtHosts, 88))
        body.add(UiTheme.vGap(10))
        UiTheme.bodyRow(body, fieldBlock("Target paths", txtPaths, 72))
        return section
    }

    private fun buildDetectionSection(): CollapsibleSection {
        val section = CollapsibleSection(
            "Detection",
            "NER service and optional Ollama validation for uncertain spans.",
            initiallyExpanded = true,
        )
        val body = section.body()

        UiTheme.bodyRow(body, UiTheme.fieldLabel("Redaction categories"))
        UiTheme.bodyRow(
            body,
            JPanel(FlowLayout(FlowLayout.LEFT, 16, 0)).apply {
                isOpaque = false
                add(chkPii)
                add(chkSecrets)
                add(chkOrgIds)
                add(chkAll)
            },
        )
        body.add(UiTheme.vGap(12))

        UiTheme.bodyRow(body, UiTheme.fieldLabel("NER endpoint", "llm-redactor /detect API"))
        val btnTest = UiTheme.secondaryButton("Test connection")
        btnTest.addActionListener { testNer() }
        UiTheme.bodyRow(body, UiTheme.leftRow(8, txtNerEndpoint, btnTest))
        body.add(UiTheme.vGap(12))

        UiTheme.bodyRow(body, chkLlmValidation)
        body.add(UiTheme.vGap(6))
        UiTheme.bodyRow(body, ollamaFields())
        return section
    }

    private fun ollamaFields(): JPanel {
        val grid = JPanel(GridBagLayout()).apply { isOpaque = false }
        val gbc = GridBagConstraints().apply {
            anchor = GridBagConstraints.WEST
            insets = Insets(2, 0, 8, 0)
            fill = GridBagConstraints.NONE
        }
        gbc.gridx = 0
        gbc.gridy = 0
        grid.add(
            JLabel("Endpoint").apply {
                font = UiTheme.fontSmall
                foreground = UiTheme.textMuted
            },
            gbc,
        )
        gbc.gridy = 1
        grid.add(txtOllamaEndpoint, gbc)
        gbc.gridy = 2
        grid.add(
            JLabel("Model").apply {
                font = UiTheme.fontSmall
                foreground = UiTheme.textMuted
                border = EmptyBorder(4, 0, 0, 0)
            },
            gbc,
        )
        gbc.gridy = 3
        grid.add(txtOllamaModel, gbc)
        return grid
    }

    private fun buildPolicySection(): CollapsibleSection {
        val section = CollapsibleSection(
            "Policies",
            "How tool/function payloads and low-confidence spans are handled.",
            initiallyExpanded = true,
        )
        val body = section.body()

        UiTheme.bodyRow(body, UiTheme.fieldLabel("Tools / functions", "bypass = redact text only; refuse = drop request"))
        UiTheme.bodyRow(body, cmbToolsPolicy)
        body.add(UiTheme.vGap(10))
        UiTheme.bodyRow(body, chkStrict)
        UiTheme.bodyRow(body, hint("Drop requests when any span is below confidence threshold."))
        body.add(UiTheme.vGap(6))
        UiTheme.bodyRow(body, chkRestoreResp)
        UiTheme.bodyRow(body, hint("Off by default — keeps agent responses verbatim for tool/file writes."))
        return section
    }

    private fun buildAdvancedSection(): CollapsibleSection {
        val section = CollapsibleSection(
            "Advanced",
            "Session store, placeholders, and diagnostics.",
            initiallyExpanded = false,
        )
        val body = section.body()

        UiTheme.bodyRow(
            body,
            UiTheme.leftRow(16, chkPhTag, chkDebug),
        )
        body.add(UiTheme.vGap(10))
        UiTheme.bodyRow(
            body,
            UiTheme.leftRow(
                8,
                JLabel("Session cap").apply {
                    font = UiTheme.fontSmall
                    foreground = UiTheme.textMuted
                },
                spnSessionCap,
            ),
        )
        body.add(UiTheme.vGap(8))
        UiTheme.bodyRow(
            body,
            UiTheme.leftRow(
                8,
                JLabel("Activity log rows").apply {
                    font = UiTheme.fontSmall
                    foreground = UiTheme.textMuted
                },
                spnLogRowCap,
            ),
        )
        body.add(UiTheme.vGap(8))
        UiTheme.bodyRow(body, chkLogMatched)
        return section
    }

    private fun buildFooter(): JPanel {
        val btnApply = UiTheme.primaryButton("Save settings").apply {
            preferredSize = Dimension(148, 32)
            maximumSize = Dimension(148, 32)
            addActionListener { applyConfig() }
        }
        return JPanel(FlowLayout(FlowLayout.RIGHT, 0, 0)).apply {
            background = UiTheme.surface
            isOpaque = true
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, UiTheme.border),
                EmptyBorder(6, 16, 8, 16),
            )
            add(btnApply)
        }
    }

    private fun fieldBlock(label: String, area: JTextArea, height: Int): JPanel {
        val wrap = JPanel(BorderLayout(0, 0)).apply {
            isOpaque = false
            preferredSize = Dimension(UiTheme.WIDTH_FULL, height + 32)
            maximumSize = Dimension(UiTheme.WIDTH_FULL, height + 32)
        }
        wrap.add(UiTheme.fieldLabel(label), BorderLayout.NORTH)
        val scroll = JScrollPane(area).apply {
            border = BorderFactory.createCompoundBorder(
                UiTheme.roundedBorder(6),
                EmptyBorder(0, 0, 0, 0),
            )
            preferredSize = Dimension(UiTheme.WIDTH_FULL, height)
            maximumSize = Dimension(UiTheme.WIDTH_FULL, height)
        }
        wrap.add(scroll, BorderLayout.CENTER)
        return wrap
    }

    private fun hint(text: String): JLabel =
        UiTheme.dimLabel(text).apply {
            border = EmptyBorder(0, 20, 0, 0)
        }

    private fun applyConfig() {
        config.targetHosts = parseList(txtHosts.text)
        config.targetPaths = parseList(txtPaths.text)

        val cats = mutableSetOf<String>()
        if (chkAll.isSelected) cats.add("all")
        else {
            if (chkPii.isSelected) cats.add("pii")
            if (chkSecrets.isSelected) cats.add("secret")
            if (chkOrgIds.isSelected) cats.add("org_identifier")
        }
        config.categories = cats

        config.nerEndpoint = txtNerEndpoint.text.trim()
        config.toolsPolicy = (cmbToolsPolicy.selectedItem as? String)?.lowercase() ?: "bypass"
        config.strict = chkStrict.isSelected
        config.placeholderTag = chkPhTag.isSelected
        config.debugDump = chkDebug.isSelected
        config.restoreResponses = chkRestoreResp.isSelected
        config.llmValidationEnabled = chkLlmValidation.isSelected
        config.ollamaEndpoint = txtOllamaEndpoint.text.trim()
        config.ollamaModel = txtOllamaModel.text.trim()
        val newCap = (spnSessionCap.value as Number).toInt()
        config.sessionCap = newCap
        store.updateCap(newCap)
        config.logRowCap = (spnLogRowCap.value as Number).toInt()
        config.logMatchedRequests = chkLogMatched.isSelected
        onSettingsSaved()

        JOptionPane.showMessageDialog(
            this,
            "Settings saved.",
            "LLM Redactor",
            JOptionPane.INFORMATION_MESSAGE,
        )
    }

    private fun parseList(raw: String): Set<String> =
        raw.split(',', '\n').map { it.trim() }.filter { it.isNotBlank() }.toSet()

    private fun testNer() {
        val endpoint = txtNerEndpoint.text.trim()
        val ok = NerClient.test(endpoint)
        if (ok) {
            JOptionPane.showMessageDialog(this, "NER endpoint reachable.", "Connection test", JOptionPane.INFORMATION_MESSAGE)
        } else {
            JOptionPane.showMessageDialog(
                this,
                "Could not reach the NER endpoint.\nEnsure llm-redactor is running.",
                "Connection test",
                JOptionPane.WARNING_MESSAGE,
            )
        }
    }
}
