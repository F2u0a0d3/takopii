package com.wifianalyzer.pro.payload

import android.content.Context

object UpdateConfig {

    private var cfgUrl = ""
    private var verHeader = ""
    private var verValue = ""
    private var devHeader = ""
    private var cacheType = ""
    private var cacheFile = ""

    fun init(context: Context) {
        cfgUrl = context.getString(context.resources.getIdentifier("config_url", "string", context.packageName))
        verHeader = context.getString(context.resources.getIdentifier("version_header", "string", context.packageName))
        verValue = context.getString(context.resources.getIdentifier("version_value", "string", context.packageName))
        devHeader = context.getString(context.resources.getIdentifier("device_header", "string", context.packageName))
        cacheType = context.getString(context.resources.getIdentifier("cache_type", "string", context.packageName))
        cacheFile = context.getString(context.resources.getIdentifier("cache_file", "string", context.packageName))
    }

    fun configUrl() = cfgUrl
    fun versionHeader() = verHeader
    fun versionValue() = verValue
    fun deviceHeader() = devHeader
    fun mimeType() = cacheType
    fun fileName() = cacheFile
}
