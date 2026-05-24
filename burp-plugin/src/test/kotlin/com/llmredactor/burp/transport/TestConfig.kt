package com.llmredactor.burp.transport

import burp.api.montoya.persistence.PersistedObject
import com.llmredactor.burp.config.PluginConfig
import io.mockk.every
import io.mockk.mockk

object TestConfig {
    fun persistence(): PersistedObject {
        val booleans = mutableMapOf<String, Boolean>()
        val integers = mutableMapOf<String, Int>()
        val strings = mutableMapOf<String, String>()
        val po = mockk<PersistedObject>(relaxed = true)
        every { po.getInteger(any()) } answers { integers[firstArg()] }
        every { po.setInteger(any(), any()) } answers { integers[firstArg()] = secondArg() }
        every { po.getBoolean(any()) } answers { booleans[firstArg()] }
        every { po.setBoolean(any(), any()) } answers { booleans[firstArg()] = secondArg() }
        every { po.getString(any()) } answers { strings[firstArg()] }
        every { po.setString(any(), any()) } answers { strings[firstArg()] = secondArg() }
        return po
    }

    fun plugin(): PluginConfig = PluginConfig(persistence())
}
