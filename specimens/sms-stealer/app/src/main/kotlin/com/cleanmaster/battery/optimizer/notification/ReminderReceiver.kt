package com.cleanmaster.battery.optimizer.notification

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.cleanmaster.battery.optimizer.NotificationHelper

class ReminderReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val title = intent.getStringExtra("title") ?: "Battery Boost"
        val message = intent.getStringExtra("message") ?: "Time for an optimization scan"
        val helper = NotificationHelper(context)
        helper.createChannels()
        helper.showScanComplete(title, message)
    }
}
