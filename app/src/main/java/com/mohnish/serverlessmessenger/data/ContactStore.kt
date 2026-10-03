package com.mohnish.serverlessmessenger.data

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import org.json.JSONArray
import org.json.JSONObject

private val Context.contactDataStore by preferencesDataStore(
    name = "serverless_contacts"
)

data class LocalContact(
    val identityId: String,
    val username: String,
    val publicKeyBase64: String,
    val agreementPublicKeyBase64: String,
    val nostrPublicKeyHex: String,
    val addedAt: Long
)

class ContactStore(
    private val context: Context
) {
    private val contactsKey =
        stringPreferencesKey("contacts_json")

    val contacts: Flow<List<LocalContact>> =
        context.contactDataStore.data.map { preferences ->
            decode(
                preferences[contactsKey] ?: "[]"
            )
        }

    suspend fun addContact(
        identityId: String,
        username: String,
        publicKeyBase64: String,
        agreementPublicKeyBase64: String,
        nostrPublicKeyHex: String
    ) {
        context.contactDataStore.edit { preferences ->

            val existing =
                decode(
                    preferences[contactsKey] ?: "[]"
                )

            if (existing.any {
                    it.identityId == identityId
                }) {
                return@edit
            }

            val updated =
                existing + LocalContact(
                    identityId = identityId,
                    username = username.trim(),
                    publicKeyBase64 = publicKeyBase64,
                    agreementPublicKeyBase64 =
                        agreementPublicKeyBase64,
                    nostrPublicKeyHex =
                        nostrPublicKeyHex,
                    addedAt =
                        System.currentTimeMillis()
                )

            preferences[contactsKey] =
                encode(updated)
        }
    }

    suspend fun removeContact(
        identityId: String
    ) {
        context.contactDataStore.edit { preferences ->

            val updated =
                decode(
                    preferences[contactsKey] ?: "[]"
                ).filterNot {
                    it.identityId == identityId
                }

            preferences[contactsKey] =
                encode(updated)
        }
    }

    private fun encode(
        contacts: List<LocalContact>
    ): String {

        val array = JSONArray()

        contacts.forEach { contact ->

            array.put(
                JSONObject().apply {
                    put(
                        "identity_id",
                        contact.identityId
                    )
                    put(
                        "username",
                        contact.username
                    )
                    put(
                        "public_key",
                        contact.publicKeyBase64
                    )
                    put(
                        "agreement_public_key",
                        contact.agreementPublicKeyBase64
                    )
                    put(
                        "nostr_public_key",
                        contact.nostrPublicKeyHex
                    )
                    put(
                        "added_at",
                        contact.addedAt
                    )
                }
            )
        }

        return array.toString()
    }

    private fun decode(
        json: String
    ): List<LocalContact> {

        return try {

            val array = JSONArray(json)

            buildList {

                for (index in 0 until array.length()) {

                    val item =
                        array.getJSONObject(index)

                    add(
                        LocalContact(
                            identityId =
                                item.getString(
                                    "identity_id"
                                ),

                            username =
                                item.optString(
                                    "username",
                                    "Unknown"
                                ).ifBlank {
                                    "Unknown"
                                },

                            publicKeyBase64 =
                                item.getString(
                                    "public_key"
                                ),

                            agreementPublicKeyBase64 =
                                item.optString(
                                    "agreement_public_key",
                                    ""
                                ),

                            nostrPublicKeyHex =
                                item.optString(
                                    "nostr_public_key",
                                    ""
                                ),

                            addedAt =
                                item.optLong(
                                    "added_at",
                                    0L
                                )
                        )
                    )
                }
            }

        } catch (_: Exception) {
            emptyList()
        }
    }
}
