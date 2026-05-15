package com.cleanmaster.battery.optimizer

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.content.Context
import android.os.Build

class BluetoothAnalyzer(private val context: Context) {

    data class BluetoothReport(
        val isEnabled: Boolean,
        val isDiscovering: Boolean,
        val bondedDeviceCount: Int,
        val bondedDevices: List<BtDeviceInfo>,
        val batteryImpact: String,
        val recommendations: List<String>
    )

    data class BtDeviceInfo(
        val name: String,
        val address: String,
        val type: String,
        val bondState: String
    )

    fun analyze(): BluetoothReport {
        val bm = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        val adapter = bm?.adapter

        val isEnabled = adapter?.isEnabled ?: false
        val isDiscovering = try { adapter?.isDiscovering ?: false } catch (_: SecurityException) { false }

        val bonded = try {
            adapter?.bondedDevices?.map { device ->
                BtDeviceInfo(
                    name = device.name ?: "Unknown",
                    address = maskAddress(device.address),
                    type = classifyDeviceType(device),
                    bondState = when (device.bondState) {
                        BluetoothDevice.BOND_BONDED -> "Paired"
                        BluetoothDevice.BOND_BONDING -> "Pairing"
                        else -> "None"
                    }
                )
            } ?: emptyList()
        } catch (_: SecurityException) { emptyList() }

        val impact = when {
            !isEnabled -> "None - Bluetooth is off"
            isDiscovering -> "High - active scanning uses significant power"
            bonded.isNotEmpty() -> "Medium - maintaining connections draws power"
            else -> "Low - Bluetooth idle with no connections"
        }

        val recs = mutableListOf<String>()
        if (isEnabled && bonded.isEmpty()) {
            recs.add("Bluetooth is enabled but no devices are connected. Turn it off to save battery.")
        }
        if (isDiscovering) {
            recs.add("Bluetooth discovery is active. This drains battery quickly.")
        }
        if (bonded.any { it.type == "Audio" }) {
            recs.add("Bluetooth audio devices draw moderate power. Use wired headphones to save battery.")
        }
        if (bonded.size > 3) {
            recs.add("Many paired devices may trigger occasional reconnection attempts.")
        }

        return BluetoothReport(
            isEnabled = isEnabled,
            isDiscovering = isDiscovering,
            bondedDeviceCount = bonded.size,
            bondedDevices = bonded,
            batteryImpact = impact,
            recommendations = recs
        )
    }

    private fun maskAddress(address: String): String {
        val parts = address.split(":")
        return if (parts.size >= 6) {
            "${parts[0]}:${parts[1]}:${parts[2]}:XX:XX:XX"
        } else address
    }

    private fun classifyDeviceType(device: BluetoothDevice): String {
        return try {
            when (device.bluetoothClass?.majorDeviceClass) {
                0x0100 -> "Computer"
                0x0200 -> "Phone"
                0x0300 -> "Network"
                0x0400 -> "Audio"
                0x0500 -> "Peripheral"
                0x0600 -> "Imaging"
                0x0700 -> "Wearable"
                else -> "Other"
            }
        } catch (_: Exception) { "Unknown" }
    }
}
