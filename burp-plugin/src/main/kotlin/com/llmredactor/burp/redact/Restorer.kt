package com.llmredactor.burp.redact

/**
 * Substitutes placeholders back to original values.
 *
 * Port of src/llm_redactor/redact/restore.py
 *
 * Only exact matches are substituted.  If the model paraphrased a
 * placeholder (dropped the brackets etc.) we leave it — that is safe.
 */
object Restorer {
    fun restore(text: String, reverseMap: Map<String, String>): String =
        reverseMap.entries.fold(text) { acc, (placeholder, original) ->
            acc.replace(placeholder, original)
        }
}
