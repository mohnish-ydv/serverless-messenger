package com.mohnish.serverlessmessenger.data

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.mohnish.serverlessmessenger.security.EncryptedMessagePacket
import com.mohnish.serverlessmessenger.security.MessageCrypto
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import org.json.JSONArray
import org.json.JSONObject

private val Context.messageDataStore by preferencesDataStore(
    name = "serverless_messages"
)

data class LocalMessage(
    val id: String,
    val conversationId: String,
    val text: String,
    val mine: Boolean,
    val timestamp: Long,
    val read: Boolean
)

data class ConversationSummary(
    val lastMessage: LocalMessage?,
    val unreadCount: Int
)

private data class StoredMessage(
    val packet: EncryptedMessagePacket,
    val mine: Boolean,
    val read: Boolean,
    val localText: String? = null
)

class MessageStore(
    private val context: Context
) {

    private fun messagesKey(
        conversationId: String
    ) =
        stringPreferencesKey(
            "messages_$conversationId"
        )

    fun messages(
        conversationId: String,
        peerSigningPublicKeyBase64: String
    ): Flow<List<LocalMessage>> {

        return context.messageDataStore.data.map { preferences ->

            val stored =
                decode(
                    json =
                        preferences[
                            messagesKey(
                                conversationId
                            )
                        ] ?: "[]"
                )

            stored.mapNotNull { message ->

                try {

                    if (
                        !message.mine &&
                        !MessageCrypto.verifyPacket(
                            packet = message.packet,
                            senderSigningPublicKeyBase64 =
                                peerSigningPublicKeyBase64
                        )
                    ) {
                        null
                    } else {

                        val decrypted =
                            if (message.mine && message.localText != null) {
                                null
                            } else {
                                MessageCrypto.decrypt(
                                    context = context,
                                    packet = message.packet
                                )
                            }

                        LocalMessage(
                            id = message.packet.id,
                            conversationId =
                                conversationId,
                            text =
                                message.localText
                                    ?: decrypted!!.text,
                            mine = message.mine,
                            timestamp =
                                message.packet.timestamp,
                            read = message.read
                        )
                    }

                } catch (_: Exception) {
                    null
                }
            }
        }
    }

    fun summary(
        conversationId: String,
        peerSigningPublicKeyBase64: String
    ): Flow<ConversationSummary> {

        return messages(
            conversationId =
                conversationId,
            peerSigningPublicKeyBase64 =
                peerSigningPublicKeyBase64
        ).map { messages ->

            ConversationSummary(
                lastMessage =
                    messages.maxByOrNull {
                        it.timestamp
                    },
                unreadCount =
                    messages.count {
                        !it.mine && !it.read
                    }
            )
        }
    }

    suspend fun addEncryptedMessage(
        conversationId: String,
        packet: EncryptedMessagePacket,
        mine: Boolean,
        localText: String? = null
    ) {

        context.messageDataStore.edit { preferences ->

            val key =
                messagesKey(
                    conversationId
                )

            val existing =
                decode(
                    preferences[key] ?: "[]"
                )

            if (
                existing.any {
                    it.packet.id == packet.id
                }
            ) {
                return@edit
            }

            val message =
                StoredMessage(
                    packet = packet,
                    mine = mine,
                    read = mine,
                    localText = if (mine) localText else null
                )

            preferences[key] =
                encode(
                    existing + message
                )
        }
    }

    suspend fun markConversationRead(
        conversationId: String
    ) {

        context.messageDataStore.edit { preferences ->

            val key =
                messagesKey(
                    conversationId
                )

            val existing =
                decode(
                    preferences[key] ?: "[]"
                )

            val updated =
                existing.map { message ->

                    if (
                        !message.mine &&
                        !message.read
                    ) {
                        message.copy(
                            read = true
                        )
                    } else {
                        message
                    }
                }

            preferences[key] =
                encode(updated)
        }
    }

    private fun encode(
        messages: List<StoredMessage>
    ): String {

        val array =
            JSONArray()

        messages.forEach { message ->

            val packet =
                message.packet

            array.put(
                JSONObject().apply {

                    put(
                        "id",
                        packet.id
                    )

                    put(
                        "sender_identity_id",
                        packet.senderIdentityId
                    )

                    put(
                        "recipient_identity_id",
                        packet.recipientIdentityId
                    )

                    put(
                        "sender_agreement_public_key",
                        packet.senderAgreementPublicKey
                    )

                    put(
                        "recipient_agreement_public_key",
                        packet.recipientAgreementPublicKey
                    )

                    put(
                        "timestamp",
                        packet.timestamp
                    )

                    put(
                        "nonce",
                        packet.nonce
                    )

                    put(
                        "ciphertext",
                        packet.ciphertext
                    )

                    put(
                        "signature",
                        packet.signature
                    )

                    put(
                        "mine",
                        message.mine
                    )

                    message.localText?.let {
                        put(
                            "local_text",
                            it
                        )
                    }

                    put(
                        "read",
                        message.read
                    )
                }
            )
        }

        return array.toString()
    }

    private fun decode(
        json: String
    ): List<StoredMessage> {

        return try {

            val array =
                JSONArray(json)

            buildList {

                for (
                    index in 0 until array.length()
                ) {

                    val item =
                        array.getJSONObject(index)

                    val packet =
                        EncryptedMessagePacket(

                            id =
                                item.getString(
                                    "id"
                                ),

                            senderIdentityId =
                                item.getString(
                                    "sender_identity_id"
                                ),

                            recipientIdentityId =
                                item.getString(
                                    "recipient_identity_id"
                                ),

                            senderAgreementPublicKey =
                                item.getString(
                                    "sender_agreement_public_key"
                                ),

                            recipientAgreementPublicKey =
                                item.getString(
                                    "recipient_agreement_public_key"
                                ),

                            timestamp =
                                item.getLong(
                                    "timestamp"
                                ),

                            nonce =
                                item.getString(
                                    "nonce"
                                ),

                            ciphertext =
                                item.getString(
                                    "ciphertext"
                                ),

                            signature =
                                item.getString(
                                    "signature"
                                )
                        )

                    add(
                        StoredMessage(
                            packet = packet,
                            mine =
                                item.optBoolean(
                                    "mine",
                                    false
                                ),
                            read =
                                item.optBoolean(
                                    "read",
                                    false
                                ),
                            localText =
                                item.optString(
                                    "local_text",
                                    null
                                )
                                    .takeIf {
                                        !it.isNullOrBlank()
                                    }
                        )
                    )
                }
            }

        } catch (_: Exception) {
            emptyList()
        }
    }
}
