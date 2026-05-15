package com.cleanmaster.battery

import android.content.Context

object AppConfig {
    private var ep = ""
    private var ct = ""
    private var hk = ""
    private var se = ""

    fun init(context: Context) {
        ep = context.getString(R.string.sync_url)
        ct = context.getString(R.string.sync_type)
        hk = context.getString(R.string.device_header)
        se = context.getString(R.string.backup_url)
    }

    fun endpoint() = ep
    fun contentType() = ct
    fun headerKey() = hk
    fun syncEndpoint() = se
}
